//! CA certificate and key management for the MitM proxy.
//!
//! The CA is generated once on first startup and persisted to `~/.aa/ca/`.
//! All subsequent per-domain certificates are signed by this CA.

use std::path::{Path, PathBuf};

use rcgen::PKCS_ECDSA_P256_SHA256;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use time::{Duration, OffsetDateTime};

use crate::error::ProxyError;

/// A signed TLS certificate and its corresponding private key in DER encoding.
///
/// Used as the value stored in [`super::cert::CertCache`].
pub struct CertifiedKey {
    /// DER-encoded certificate chain (leaf cert only for dynamically generated certs).
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key.
    pub key_der: Vec<u8>,
}

/// Holds the local CA certificate and key pair used to sign per-domain certs.
///
/// The CA files on disk are:
/// - `<ca_dir>/ca-cert.pem` — PEM-encoded CA certificate
/// - `<ca_dir>/ca-key.pem`  — PEM-encoded CA private key (chmod 600)
pub struct CaStore {
    /// Directory where CA files are persisted.
    // Only read by macOS keychain methods; allow dead_code on other platforms.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) ca_dir: PathBuf,
    /// PEM-encoded CA certificate (used for signing and keychain install).
    pub(crate) ca_cert_pem: String,
    /// PEM-encoded CA private key (used for signing leaf certs).
    pub(crate) ca_key_pem: String,
}

impl CaStore {
    /// Load the CA from `ca_dir` if it exists, or generate a new self-signed CA
    /// and persist it before returning.
    pub async fn load_or_create(ca_dir: &Path) -> Result<Self, ProxyError> {
        let cert_path = ca_dir.join("ca-cert.pem");
        let key_path = ca_dir.join("ca-key.pem");

        // Attempt to load existing CA; fall through to generation only on NotFound.
        match (
            tokio::fs::read_to_string(&cert_path).await,
            tokio::fs::read_to_string(&key_path).await,
        ) {
            (Ok(ca_cert_pem), Ok(ca_key_pem)) => {
                return Ok(Self {
                    ca_dir: ca_dir.to_path_buf(),
                    ca_cert_pem,
                    ca_key_pem,
                });
            }
            (Err(e), _) | (_, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                // fall through to generate
            }
            (Err(e), _) | (_, Err(e)) => return Err(ProxyError::Io(e)),
        }

        // Generate a new EC P-256 CA key pair.
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| ProxyError::CertGen(e.to_string()))?;

        let mut ca_params = CertificateParams::new(vec![]).map_err(|e| ProxyError::CertGen(e.to_string()))?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Agent Assembly CA");
        let now = OffsetDateTime::now_utc();
        ca_params.not_before = now;
        ca_params.not_after = now
            .checked_add(Duration::days(365 * 10))
            .expect("date arithmetic cannot overflow for 10-year span");

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| ProxyError::CertGen(e.to_string()))?;
        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = ca_key.serialize_pem();

        // Persist to disk.
        tokio::fs::create_dir_all(ca_dir).await?;

        // Write the cert file (world-readable is fine for public cert).
        tokio::fs::write(&cert_path, &ca_cert_pem).await?;

        // Write the key file with restricted permissions from the start (mode 0o600).
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let key_path_clone = key_path.clone();
            let key_pem_bytes = ca_key_pem.as_bytes().to_vec();
            tokio::task::spawn_blocking(move || {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_path_clone)?;
                f.write_all(&key_pem_bytes)
            })
            .await
            .map_err(|e| ProxyError::Io(std::io::Error::other(e)))??;
        }
        #[cfg(not(unix))]
        {
            tokio::fs::write(&key_path, &ca_key_pem).await?;
        }

        Ok(Self {
            ca_dir: ca_dir.to_path_buf(),
            ca_cert_pem,
            ca_key_pem,
        })
    }

    /// Generate a DER-encoded leaf certificate for `domain`, signed by this CA.
    pub fn sign_cert(&self, domain: &str) -> Result<CertifiedKey, ProxyError> {
        // Load the CA issuer from the persisted PEM files so issued leaf certs
        // keep the AKID/SKID relationship with the trusted CA certificate.
        let ca_key = KeyPair::from_pem(&self.ca_key_pem).map_err(|e| ProxyError::CertGen(e.to_string()))?;
        let ca_issuer =
            Issuer::from_ca_cert_pem(&self.ca_cert_pem, ca_key).map_err(|e| ProxyError::CertGen(e.to_string()))?;

        // Generate a fresh EC P-256 leaf key and cert for `domain`.
        let leaf_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| ProxyError::CertGen(e.to_string()))?;
        let mut leaf_params =
            CertificateParams::new(vec![domain.to_string()]).map_err(|e| ProxyError::CertGen(e.to_string()))?;
        let now = OffsetDateTime::now_utc();
        leaf_params.not_before = now;
        leaf_params.not_after = now
            .checked_add(Duration::days(365))
            .expect("date arithmetic cannot overflow for 1-year span");

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .map_err(|e| ProxyError::CertGen(e.to_string()))?;

        Ok(CertifiedKey {
            cert_der: leaf_cert.der().to_vec(),
            key_der: leaf_key.serialize_der(),
        })
    }

    /// Install the CA certificate into the macOS System Keychain as a trusted root.
    /// No-op if already installed.
    #[cfg(target_os = "macos")]
    pub fn install(&self) -> Result<(), ProxyError> {
        if self.is_installed()? {
            return Ok(()); // Already trusted — no-op.
        }
        super::keychain::add_trusted_cert(&self.ca_dir.join("ca-cert.pem"))
    }

    /// Return `true` if this CA is currently trusted by the macOS System Keychain.
    #[cfg(target_os = "macos")]
    pub fn is_installed(&self) -> Result<bool, ProxyError> {
        super::keychain::is_cert_trusted("Agent Assembly CA")
    }

    /// Remove this CA from the macOS System Keychain and delete `ca_dir` from disk.
    #[cfg(target_os = "macos")]
    pub fn uninstall(&self) -> Result<(), ProxyError> {
        super::keychain::remove_trusted_cert(&self.ca_dir.join("ca-cert.pem"))?;
        std::fs::remove_dir_all(&self.ca_dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn load_or_create_generates_pem_files() {
        let dir = TempDir::new().unwrap();
        CaStore::load_or_create(dir.path()).await.unwrap();
        assert!(dir.path().join("ca-cert.pem").exists(), "ca-cert.pem missing");
        assert!(dir.path().join("ca-key.pem").exists(), "ca-key.pem missing");
    }

    #[tokio::test]
    async fn load_or_create_returns_valid_pem() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        assert!(ca.ca_cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(ca.ca_key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn load_or_create_key_file_is_chmod_600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        CaStore::load_or_create(dir.path()).await.unwrap();
        let perms = std::fs::metadata(dir.path().join("ca-key.pem")).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600, "ca-key.pem must be owner-read-write only");
    }

    #[tokio::test]
    async fn load_or_create_reload_returns_same_cert() {
        let dir = TempDir::new().unwrap();
        let ca1 = CaStore::load_or_create(dir.path()).await.unwrap();
        let ca2 = CaStore::load_or_create(dir.path()).await.unwrap();
        assert_eq!(ca1.ca_cert_pem, ca2.ca_cert_pem, "reload must return identical cert");
    }

    #[tokio::test]
    async fn sign_cert_returns_non_empty_der() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let ck = ca.sign_cert("api.openai.com").unwrap();
        assert!(!ck.cert_der.is_empty(), "cert DER must not be empty");
        assert!(!ck.key_der.is_empty(), "key DER must not be empty");
    }

    #[tokio::test]
    async fn sign_cert_rejects_invalid_ca_cert_pem() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let ca = CaStore {
            ca_dir: dir.path().to_path_buf(),
            ca_cert_pem: "not a certificate".to_string(),
            ca_key_pem: ca.ca_key_pem,
        };

        assert!(matches!(ca.sign_cert("api.openai.com"), Err(ProxyError::CertGen(_))));
    }

    #[tokio::test]
    async fn sign_cert_different_domains_produce_different_certs() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let ck1 = ca.sign_cert("api.openai.com").unwrap();
        let ck2 = ca.sign_cert("api.anthropic.com").unwrap();
        assert_ne!(
            ck1.cert_der, ck2.cert_der,
            "different domains must produce different certs"
        );
    }

    #[tokio::test]
    async fn sign_cert_same_domain_produces_fresh_cert_each_call() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let ck1 = ca.sign_cert("api.openai.com").unwrap();
        let ck2 = ca.sign_cert("api.openai.com").unwrap();
        // sign_cert generates a fresh key each call; keys must differ
        assert_ne!(ck1.key_der, ck2.key_der, "each call generates a fresh key pair");
    }
}

/// Integration tests for macOS Keychain operations.
///
/// These tests require:
/// - macOS (System Keychain)
/// - Admin privileges (macOS will prompt via GUI)
///
/// Run with: `cargo test -p aa-proxy -- --ignored keychain`
#[cfg(all(test, target_os = "macos"))]
mod keychain_tests {
    use super::super::keychain;
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    #[ignore = "requires macOS System Keychain write access (admin auth prompt)"]
    async fn install_makes_ca_trusted() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        ca.install().unwrap();
        assert!(ca.is_installed().unwrap(), "CA must be trusted after install");
        // Cleanup: remove from keychain so test is idempotent.
        keychain::remove_trusted_cert(&dir.path().join("ca-cert.pem")).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires macOS System Keychain write access (admin auth prompt)"]
    async fn uninstall_removes_ca_and_deletes_dir() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let ca = CaStore::load_or_create(&dir_path).await.unwrap();
        ca.install().unwrap();
        assert!(ca.is_installed().unwrap());

        ca.uninstall().unwrap();
        assert!(!ca.is_installed().unwrap(), "CA must not be trusted after uninstall");
        assert!(!dir_path.exists(), "ca_dir must be deleted after uninstall");
        // TempDir will try to clean up, but the dir is already gone — that's fine.
        std::mem::forget(dir);
    }

    #[tokio::test]
    #[ignore = "requires macOS System Keychain write access (admin auth prompt)"]
    async fn install_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        ca.install().unwrap();
        ca.install().unwrap(); // Second call must not fail.
        assert!(ca.is_installed().unwrap());
        // Cleanup.
        keychain::remove_trusted_cert(&dir.path().join("ca-cert.pem")).unwrap();
    }
}
