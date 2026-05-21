//! Pre-flight TLS validation for Remote Control-Plane Mode.
//!
//! The gateway calls [`validate`] before binding the listener so any
//! cert / key misconfiguration produces a fast, clearly-attributed
//! startup error rather than a runtime TLS handshake failure that
//! shows up only when the first client tries to connect.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aa_core::config::TlsConfig;
use thiserror::Error;

/// Outcome of a successful [`validate`] call — the cert parsed, but
/// classification distinguishes "fine" from soft warnings about its
/// remaining lifetime.
///
/// The caller decides whether `ExpiringSoon` and `Expired` produce
/// log lines or hard startup errors; this type only reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsValidation {
    /// Cert parsed and is not within 30 days of expiry.
    Ok,
    /// Cert parsed but expires within 30 days. Operator should rotate.
    ExpiringSoon {
        /// Whole days remaining until `notAfter`.
        days_until_expiry: i64,
    },
    /// Cert parsed but `notAfter` is already in the past. The gateway
    /// can still start, but new TLS clients will reject the chain.
    Expired {
        /// Whole days since `notAfter`.
        expired_days_ago: i64,
    },
}

/// Threshold below which a cert is reported as `ExpiringSoon`.
const EXPIRING_SOON_DAYS: i64 = 30;

/// Seconds in one day, used to convert between Unix-epoch seconds and
/// whole-day deltas.
const SECONDS_PER_DAY: i64 = 86_400;

/// Validate a [`TlsConfig`] before binding the listener.
///
/// Steps, in order:
///
/// 1. `cert_file` and `key_file` exist on disk.
/// 2. Both files are readable (open + read into memory).
/// 3. The cert file decodes as PEM-wrapped X.509.
/// 4. The leaf cert's `notAfter` is classified — `Ok` /
///    `ExpiringSoon` (≤ 30 days) / `Expired` (in the past).
///
/// Returns `Err(TlsError)` for hard failures the gateway must surface
/// before binding. Returns `Ok(TlsValidation::*)` when the cert parsed,
/// leaving log-vs-fail policy for expiry warnings to the caller.
pub fn validate(cfg: &TlsConfig) -> Result<TlsValidation, TlsError> {
    if !cfg.cert_file.exists() {
        return Err(TlsError::CertFileMissing(cfg.cert_file.clone()));
    }
    if !cfg.key_file.exists() {
        return Err(TlsError::KeyFileMissing(cfg.key_file.clone()));
    }

    let cert_bytes = read_file(&cfg.cert_file)?;
    // Key file is read purely as a readability check — handshake-time
    // parsing happens in axum-server::tls_rustls when ST-3 binds.
    let _key_bytes = read_file(&cfg.key_file)?;

    let mut reader = BufReader::new(cert_bytes.as_slice());
    let leaf_der = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| TlsError::CertParse("no certificate found in PEM".to_string()))?
        .map_err(|e| TlsError::CertParse(format!("pem decode: {e}")))?;

    let (_, x509) =
        x509_parser::parse_x509_certificate(&leaf_der).map_err(|e| TlsError::CertParse(format!("x509 decode: {e}")))?;

    let not_after_secs = x509.validity().not_after.timestamp();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let days_until = (not_after_secs - now_secs) / SECONDS_PER_DAY;

    if days_until < 0 {
        Ok(TlsValidation::Expired {
            expired_days_ago: -days_until,
        })
    } else if days_until <= EXPIRING_SOON_DAYS {
        Ok(TlsValidation::ExpiringSoon {
            days_until_expiry: days_until,
        })
    } else {
        Ok(TlsValidation::Ok)
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, TlsError> {
    fs::read(path).map_err(|source| TlsError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Hard failures that should stop gateway startup in remote-mode TLS.
///
/// The variant carries enough context (paths, parse messages) for the
/// startup log line to point an operator at exactly the file or field
/// that needs fixing.
#[derive(Debug, Error)]
pub enum TlsError {
    /// The configured `cert_file` path does not exist on disk.
    #[error("TLS cert_file not found: {0}")]
    CertFileMissing(PathBuf),

    /// The configured `key_file` path does not exist on disk.
    #[error("TLS key_file not found: {0}")]
    KeyFileMissing(PathBuf),

    /// I/O error reading cert or key file (e.g. permission denied).
    #[error("failed to read TLS file {path}: {source}")]
    Io {
        /// File the gateway tried to read.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The cert file does not parse as PEM-encoded X.509.
    #[error("failed to parse TLS cert as PEM x509: {0}")]
    CertParse(String),
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use tempfile::TempDir;
    use time::{Duration as TimeDuration, OffsetDateTime};

    use super::*;

    /// Generate a self-signed cert with custom validity offsets (in days
    /// from `now`). Returns the PEM bytes for cert and key.
    fn issue_cert_with_validity(not_before_days: i64, not_after_days: i64) -> (Vec<u8>, Vec<u8>) {
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(vec!["test.example".to_string()]).expect("params");
        params.not_before = now + TimeDuration::days(not_before_days);
        params.not_after = now + TimeDuration::days(not_after_days);

        let key_pair = KeyPair::generate().expect("key_pair");
        let cert = params.self_signed(&key_pair).expect("self-signed");
        (cert.pem().into_bytes(), key_pair.serialize_pem().into_bytes())
    }

    /// Write cert + key PEM bytes into a temp dir, returning a [`TlsConfig`]
    /// pointing at the written paths. The `TempDir` is returned so the caller
    /// can keep it alive for the duration of the test (Drop deletes the files).
    fn write_pair(cert_pem: &[u8], key_pem: &[u8]) -> (TempDir, TlsConfig) {
        let dir = TempDir::new().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        fs::write(&cert_path, cert_pem).expect("write cert");
        fs::write(&key_path, key_pem).expect("write key");
        let cfg = TlsConfig {
            cert_file: cert_path,
            key_file: key_path,
        };
        (dir, cfg)
    }

    #[test]
    fn returns_ok_for_fresh_year_long_cert() {
        let (cert, key) = issue_cert_with_validity(-1, 365);
        let (_dir, cfg) = write_pair(&cert, &key);
        assert_eq!(validate(&cfg).expect("validate"), TlsValidation::Ok);
    }

    #[test]
    fn flags_expiring_soon_within_30_days() {
        let (cert, key) = issue_cert_with_validity(-1, 10);
        let (_dir, cfg) = write_pair(&cert, &key);
        let result = validate(&cfg).expect("validate");
        match result {
            TlsValidation::ExpiringSoon { days_until_expiry } => {
                // Allow a one-day slack on each side — UTC midnight rollover
                // between cert issue and validate() could shift the bucket
                // by one full day on a slow CI runner.
                assert!(
                    (9..=10).contains(&days_until_expiry),
                    "expected days_until_expiry in 9..=10, got {days_until_expiry}"
                );
            }
            other => panic!("expected ExpiringSoon, got {other:?}"),
        }
    }

    #[test]
    fn flags_expired_for_past_not_after() {
        // not_before 100 days ago, not_after 7 days ago.
        let (cert, key) = issue_cert_with_validity(-100, -7);
        let (_dir, cfg) = write_pair(&cert, &key);
        let result = validate(&cfg).expect("validate");
        match result {
            TlsValidation::Expired { expired_days_ago } => {
                assert!(
                    (6..=7).contains(&expired_days_ago),
                    "expected expired_days_ago in 6..=7, got {expired_days_ago}"
                );
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn errors_when_cert_file_missing() {
        let (cert, key) = issue_cert_with_validity(-1, 365);
        let (dir, mut cfg) = write_pair(&cert, &key);
        cfg.cert_file = dir.path().join("does-not-exist.pem");
        match validate(&cfg).expect_err("expected error") {
            TlsError::CertFileMissing(path) => assert_eq!(path, cfg.cert_file),
            other => panic!("expected CertFileMissing, got {other:?}"),
        }
    }

    #[test]
    fn errors_when_key_file_missing() {
        let (cert, key) = issue_cert_with_validity(-1, 365);
        let (dir, mut cfg) = write_pair(&cert, &key);
        cfg.key_file = dir.path().join("missing-key.pem");
        match validate(&cfg).expect_err("expected error") {
            TlsError::KeyFileMissing(path) => assert_eq!(path, cfg.key_file),
            other => panic!("expected KeyFileMissing, got {other:?}"),
        }
    }

    #[test]
    fn errors_when_cert_is_not_pem() {
        let (_real_cert, key) = issue_cert_with_validity(-1, 365);
        // Junk bytes that pass existence + read checks but fail PEM parse.
        let junk = b"this is not a PEM-wrapped X.509 cert".to_vec();
        let (_dir, cfg) = write_pair(&junk, &key);
        match validate(&cfg).expect_err("expected error") {
            TlsError::CertParse(_) => {}
            other => panic!("expected CertParse, got {other:?}"),
        }
    }
}
