//! CA certificate and key management for the MitM proxy.
//!
//! The CA is generated once on first startup and persisted to `~/.aa/ca/`.
//! All subsequent per-domain certificates are signed by this CA.

use std::path::{Path, PathBuf};

use rcgen::PKCS_ECDSA_P256_SHA256;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DnType, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use time::{Duration, OffsetDateTime};

use crate::error::ProxyError;

/// Build the [`CertificateParams`] for the MitM root CA.
///
/// AAASM-4133 — the CA is installed as a system trust root with 10-year
/// validity, so a leak of `~/.aa/ca/ca-key.pem` is high-impact. The proxy only
/// ever signs leaf certs for *outbound public egress* endpoints, so the CA is
/// name-constrained to **exclude** the internal / private namespaces it never
/// legitimately intercepts: loopback, mDNS (`.local`), `.internal`,
/// `home.arpa`, and the RFC 1918 / loopback / link-local / IPv6 ULA IP ranges.
/// A leaked key then cannot mint trusted certs impersonating those internal
/// services. Only excluded subtrees are set (no permitted list), so
/// interception of arbitrary *public* domains is unchanged.
fn build_ca_params() -> Result<CertificateParams, ProxyError> {
    let mut ca_params = CertificateParams::new(vec![]).map_err(|e| ProxyError::CertGen(e.to_string()))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Agent Assembly CA");
    ca_params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![
            GeneralSubtree::DnsName("localhost".into()),
            GeneralSubtree::DnsName("local".into()),
            GeneralSubtree::DnsName("internal".into()),
            GeneralSubtree::DnsName("home.arpa".into()),
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([10, 0, 0, 0], 8)),
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([172, 16, 0, 0], 12)),
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([192, 168, 0, 0], 16)),
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([127, 0, 0, 0], 8)),
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([169, 254, 0, 0], 16)),
            // ::1/128 loopback, fc00::/7 unique-local, fe80::/10 link-local.
            GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                128,
            )),
            GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix(
                [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                7,
            )),
            GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                10,
            )),
        ],
    });
    let now = OffsetDateTime::now_utc();
    ca_params.not_before = now;
    ca_params.not_after = now
        .checked_add(Duration::days(365 * 10))
        .expect("date arithmetic cannot overflow for 10-year span");
    Ok(ca_params)
}

/// Return whether `ca_key_pem` is the private key belonging to `ca_cert_pem`.
///
/// AAASM-5928: compares the key's raw EC public key point against the
/// certificate's SubjectPublicKeyInfo rather than any weaker heuristic (e.g.
/// just successfully parsing both) — both `rcgen::KeyPair::public_key_raw`
/// and x509-parser's `SubjectPublicKeyInfo::subject_public_key` store the
/// same raw uncompressed EC point for a P-256 key (the only curve this CA
/// ever generates), so a direct byte comparison is a correct and cheap
/// matched-pair check with no extra crypto operations needed.
fn ca_pair_matches(ca_cert_pem: &str, ca_key_pem: &str) -> Result<bool, ProxyError> {
    let key = KeyPair::from_pem(ca_key_pem).map_err(|e| ProxyError::CertGen(e.to_string()))?;

    let (_, pem) =
        x509_parser::pem::parse_x509_pem(ca_cert_pem.as_bytes()).map_err(|e| ProxyError::CertGen(e.to_string()))?;
    let cert = pem.parse_x509().map_err(|e| ProxyError::CertGen(e.to_string()))?;

    Ok(cert.public_key().subject_public_key.data.as_ref() == key.public_key_raw())
}

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
    ///
    /// AAASM-5862 deliberately keeps `ca_dir` SHARED across every launch on a
    /// machine (a per-launch dir would mint a fresh CA — and trigger a macOS
    /// Keychain trust re-prompt — every run). That means this method must be
    /// safe when multiple processes race to initialize the same shared dir
    /// for the first time. AAASM-5928 found a real corrupted pair on a
    /// multi-session dev machine caused by exactly that race: two processes'
    /// non-atomic, uncoordinated cert/key writes interleaved into a torn
    /// mismatched pair, which broke every downstream TLS handshake with
    /// `CERT_SIGNATURE_FAILURE`. This method now (1) verifies a loaded pair
    /// is actually matched before trusting it, and (2) serializes
    /// generate-and-persist across processes via an O_EXCL lock file plus
    /// temp-file-then-atomic-rename, so no reader can ever observe a torn
    /// write.
    pub async fn load_or_create(ca_dir: &Path) -> Result<Self, ProxyError> {
        let cert_path = ca_dir.join("ca-cert.pem");
        let key_path = ca_dir.join("ca-key.pem");
        let lock_path = ca_dir.join(".ca-lock");

        // AAASM-5928 CI regression: `ca_dir` is a fresh, never-created Docker
        // volume mount on a container's first-ever start — every existing test
        // here used `TempDir::new()`, which always pre-exists, so this path was
        // never exercised locally. Without this, the O_EXCL lock-file
        // `create_new` below is the first filesystem operation against a
        // missing parent directory and fails with `ErrorKind::NotFound`, which
        // isn't handled by the `AlreadyExists` retry arm and falls through to
        // the generic `Err` arm that returns immediately — so `run()` errors
        // out before the TCP listener ever binds. The container's restart
        // policy then crash-loops on the same immediate failure forever, which
        // from outside the container looks identical to "the proxy is hanging
        // and never accepts connections."
        tokio::fs::create_dir_all(ca_dir).await?;

        // Bounds on how long a caller will wait for another process's
        // in-flight generation before giving up, and how old an unreleased
        // lock file must be before it's treated as abandoned by a crashed
        // holder rather than a live one. A crashed holder that never gets
        // reclaimed would wedge this shared, multi-session directory for
        // every subsequent launch forever — exactly the kind of persistent
        // breakage this ticket exists to prevent.
        const MAX_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
        const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

        let started = std::time::Instant::now();
        let mut backoff = std::time::Duration::from_millis(10);

        loop {
            if let Some(store) = Self::try_load_matched_pair(ca_dir, &cert_path, &key_path).await? {
                return Ok(store);
            }

            // No matched pair on disk (missing, or a real mismatch that must
            // be treated as absent and regenerated). Acquire the lock via an
            // O_EXCL create — atomic file creation as the mutual-exclusion
            // primitive, rather than pulling in an flock crate (fs2/fd-lock)
            // for the one call site that needs it.
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
                .await
            {
                Ok(_lock_file) => {
                    // Re-check under the lock: the previous holder may have
                    // finished generating while we were racing to acquire it.
                    let result = if let Some(store) = Self::try_load_matched_pair(ca_dir, &cert_path, &key_path).await?
                    {
                        Ok(store)
                    } else {
                        Self::generate_and_persist(ca_dir, &cert_path, &key_path).await
                    };
                    // Always release, even on error — a failed generation
                    // must not leave the shared dir locked out forever.
                    let _ = tokio::fs::remove_file(&lock_path).await;
                    return result;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let lock_is_stale = tokio::fs::metadata(&lock_path)
                        .await
                        .ok()
                        .and_then(|meta| meta.modified().ok())
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|age| age > LOCK_STALE_AFTER);
                    if lock_is_stale {
                        let _ = tokio::fs::remove_file(&lock_path).await;
                        continue;
                    }
                    if started.elapsed() > MAX_LOCK_WAIT {
                        return Err(ProxyError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "timed out waiting for CA store lock",
                        )));
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(std::time::Duration::from_millis(200));
                }
                Err(e) => return Err(ProxyError::Io(e)),
            }
        }
    }

    /// Load `cert_path`/`key_path` if both exist and are a genuinely matched
    /// pair; return `None` if either is missing or they don't match.
    ///
    /// AAASM-5928: file existence alone was the pre-fix bug — a cert and key
    /// found on disk were never checked to actually belong together, so a
    /// torn write from a concurrent first-time init was silently served as
    /// valid. A mismatch here must be handled exactly like "not generated
    /// yet" by the caller, never returned as-is.
    async fn try_load_matched_pair(
        ca_dir: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Option<Self>, ProxyError> {
        let (ca_cert_pem, ca_key_pem) = match (
            tokio::fs::read_to_string(cert_path).await,
            tokio::fs::read_to_string(key_path).await,
        ) {
            (Ok(ca_cert_pem), Ok(ca_key_pem)) => (ca_cert_pem, ca_key_pem),
            (Err(e), _) | (_, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            (Err(e), _) | (_, Err(e)) => return Err(ProxyError::Io(e)),
        };

        if !ca_pair_matches(&ca_cert_pem, &ca_key_pem)? {
            return Ok(None);
        }

        // AAASM-4936 (L4): 0600 is enforced only at creation time, so a
        // key written by an older build, restored from a backup, or
        // copied in with loose perms would be served group/other-
        // readable. Re-assert 0600 on every load so the private key can
        // never be left world-readable across a proxy restart.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_path_clone = key_path.to_path_buf();
            tokio::task::spawn_blocking(move || {
                std::fs::set_permissions(&key_path_clone, std::fs::Permissions::from_mode(0o600))
            })
            .await
            .map_err(|e| ProxyError::Io(std::io::Error::other(e)))??;
        }

        Ok(Some(Self {
            ca_dir: ca_dir.to_path_buf(),
            ca_cert_pem,
            ca_key_pem,
        }))
    }

    /// Generate a fresh CA key pair and persist it to `cert_path`/`key_path`.
    ///
    /// Only ever called by the caller holding `load_or_create`'s lock, so
    /// there is exactly one writer. Still writes through a per-process temp
    /// file and an atomic same-directory rename (AAASM-5928) so a losing
    /// racer that reloads after the lock is released — or any other
    /// reader — can never observe a partially-written file, and so a
    /// process that crashes mid-write leaves only a stray temp file rather
    /// than a torn final file.
    async fn generate_and_persist(ca_dir: &Path, cert_path: &Path, key_path: &Path) -> Result<Self, ProxyError> {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| ProxyError::CertGen(e.to_string()))?;

        let ca_params = build_ca_params()?;

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| ProxyError::CertGen(e.to_string()))?;
        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = ca_key.serialize_pem();

        tokio::fs::create_dir_all(ca_dir).await?;

        let pid = std::process::id();
        let cert_tmp = ca_dir.join(format!("ca-cert.pem.tmp-{pid}"));
        let key_tmp = ca_dir.join(format!("ca-key.pem.tmp-{pid}"));

        // Write the cert temp file (world-readable is fine for public cert).
        tokio::fs::write(&cert_tmp, &ca_cert_pem).await?;

        // Write the key temp file with restricted permissions from the start (mode 0o600).
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let key_tmp_clone = key_tmp.clone();
            let key_pem_bytes = ca_key_pem.as_bytes().to_vec();
            tokio::task::spawn_blocking(move || {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_tmp_clone)?;
                f.write_all(&key_pem_bytes)
            })
            .await
            .map_err(|e| ProxyError::Io(std::io::Error::other(e)))??;
        }
        #[cfg(not(unix))]
        {
            tokio::fs::write(&key_tmp, &ca_key_pem).await?;
        }

        // Rename is atomic on the same filesystem — this is the point at
        // which each file becomes visible to other readers, never before.
        tokio::fs::rename(&cert_tmp, cert_path).await?;
        tokio::fs::rename(&key_tmp, key_path).await?;

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

    #[test]
    fn ca_cert_carries_name_constraints_extension() {
        // AAASM-4133: the root CA must be name-constrained. The X.509
        // NameConstraints extension is OID 2.5.29.30, which DER-encodes to the
        // byte sequence `06 03 55 1D 1E`; assert it appears in the cert DER.
        let params = build_ca_params().unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();
        let needle = [0x06u8, 0x03, 0x55, 0x1d, 0x1e];
        assert!(
            der.as_ref().windows(needle.len()).any(|w| w == needle),
            "CA cert must carry the X.509 NameConstraints extension (OID 2.5.29.30)"
        );
    }

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

    /// AAASM-4936 (L4): perms are enforced only at creation, so a key that
    /// already exists with loose perms (older build, restored backup, manual
    /// copy) must be re-tightened to 0600 when it is loaded.
    #[tokio::test]
    #[cfg(unix)]
    async fn load_or_create_reasserts_600_on_loose_existing_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        // First create a valid CA, then loosen the key perms to world-readable.
        CaStore::load_or_create(dir.path()).await.unwrap();
        let key_path = dir.path().join("ca-key.pem");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        // Loading the existing CA must re-tighten the key to 0600.
        CaStore::load_or_create(dir.path()).await.unwrap();
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "load must re-assert 0600 on an existing loose key"
        );
    }

    /// AAASM-5928 CI regression repro: the real proxy's `ca_dir` is a fresh,
    /// never-created Docker volume mount on first-ever container start — unlike
    /// every other test here, which uses `TempDir::new()` (always pre-existing).
    /// Reproduces against a `ca_dir` path that does not exist yet.
    #[tokio::test]
    async fn load_or_create_succeeds_when_ca_dir_does_not_exist_yet() {
        let parent = TempDir::new().unwrap();
        let ca_dir = parent.path().join("does").join("not").join("exist");
        assert!(!ca_dir.exists(), "test fixture must start absent");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), CaStore::load_or_create(&ca_dir)).await;

        let ca = result
            .expect("load_or_create must not hang when ca_dir does not exist yet")
            .expect("load_or_create must succeed when ca_dir does not exist yet");
        assert!(
            ca_pair_matches(&ca.ca_cert_pem, &ca.ca_key_pem).unwrap(),
            "must return a matched pair even on a first-ever cold start"
        );
    }

    #[tokio::test]
    async fn load_or_create_reload_returns_same_cert() {
        let dir = TempDir::new().unwrap();
        let ca1 = CaStore::load_or_create(dir.path()).await.unwrap();
        let ca2 = CaStore::load_or_create(dir.path()).await.unwrap();
        assert_eq!(ca1.ca_cert_pem, ca2.ca_cert_pem, "reload must return identical cert");
    }

    /// AAASM-5928: reproduces the real mismatched-keypair race — many
    /// processes on a shared multi-session machine can all reach
    /// `load_or_create` for the very first time against the same shared
    /// `ca_dir` simultaneously. Every caller must observe a matched pair,
    /// and what ends up persisted on disk afterward must also be matched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn load_or_create_is_race_safe_under_concurrent_first_init() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let path = path.clone();
            tasks.spawn(async move { CaStore::load_or_create(&path).await });
        }

        let mut results = Vec::new();
        while let Some(res) = tasks.join_next().await {
            results.push(res.unwrap().unwrap());
        }
        assert_eq!(results.len(), 16, "every concurrent caller must succeed");

        for ca in &results {
            assert!(
                ca_pair_matches(&ca.ca_cert_pem, &ca.ca_key_pem).unwrap(),
                "every concurrent caller must observe a matched cert/key pair"
            );
        }

        let persisted_cert = tokio::fs::read_to_string(path.join("ca-cert.pem")).await.unwrap();
        let persisted_key = tokio::fs::read_to_string(path.join("ca-key.pem")).await.unwrap();
        assert!(
            ca_pair_matches(&persisted_cert, &persisted_key).unwrap(),
            "the persisted cert/key pair on disk must be matched"
        );
    }

    /// AAASM-5928: simulates the actual corruption found on a real shared dev
    /// machine — a cert from one CA generation paired with the key from a
    /// different, unrelated generation. `load_or_create` must detect the
    /// mismatch and regenerate through the locked path rather than serving
    /// the corrupt pair.
    #[tokio::test]
    async fn load_or_create_recovers_from_mismatched_pair_on_disk() {
        let dir = TempDir::new().unwrap();

        let key_a = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params_a = build_ca_params().unwrap();
        let cert_a = params_a.self_signed(&key_a).unwrap();

        let key_b = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();

        // Cert from generation A, key from unrelated generation B.
        tokio::fs::write(dir.path().join("ca-cert.pem"), cert_a.pem())
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("ca-key.pem"), key_b.serialize_pem())
            .await
            .unwrap();
        assert!(
            !ca_pair_matches(&cert_a.pem(), &key_b.serialize_pem()).unwrap(),
            "test fixture must actually be mismatched"
        );

        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        assert!(
            ca_pair_matches(&ca.ca_cert_pem, &ca.ca_key_pem).unwrap(),
            "load_or_create must return a self-consistent pair even when disk started mismatched"
        );
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
