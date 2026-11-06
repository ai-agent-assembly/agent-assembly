//! Authenticated organization binding for agent registration (AAASM-6444).
//!
//! `AgentLifecycleService.Register` is the one place an agent's organization is
//! decided, and every later surface (audit lineage, `?org_id=` filters,
//! policy cascade, budget envelope) reads it back from the registry record. A
//! registration used to copy `AgentId.org_id` verbatim from the request, so any
//! caller that could reach the gRPC port could register into any organization.
//!
//! The org now comes from an operator credential presented on the registration
//! call: an `aa_…` API key from the same `aa-auth` key store that already binds
//! REST callers to a tenant (`ApiKeyEntry::org_id`, AAASM-3139). A client-sent
//! `AgentId.org_id` is only a *claim*, checked against that binding.
//!
//! | credential               | claimed org | result                                   |
//! |--------------------------|-------------|------------------------------------------|
//! | none                     | empty       | org-less agent (legacy / OSS default)    |
//! | none                     | `X`         | rejected `PermissionDenied`              |
//! | invalid / revoked/expired| any         | rejected `Unauthenticated`               |
//! | bound to org `O`         | empty       | org `O` (derived)                        |
//! | bound to org `O`         | `O`         | org `O`                                  |
//! | bound to org `O`         | other       | rejected `PermissionDenied` (spoof)      |
//! | admin, no org binding    | `X`         | org `X` (operator-authorised assertion)  |
//! | non-admin, no binding    | `X`         | rejected `PermissionDenied`              |
//! | non-admin, no binding    | empty       | org-less agent                           |
//!
//! `team_id` is never read as an organization.

use std::sync::Arc;

use aa_auth::api_key::{ApiKeyStore, KeyNotValid};
use aa_auth::scope::Scope;
use tonic::{Request, Status};

/// Metric incremented for every registration refused by the org binding,
/// labelled `reason = "unauthenticated" | "no_credential" | "mismatch" | "unbound_key"`.
pub const METRIC_REGISTER_ORG_REJECTED: &str = "aa_register_org_rejected_total";

/// gRPC metadata key carrying the operator API key on `Register` /
/// `RequestChallenge`. Deliberately not `authorization`: that header carries the
/// agent credential token on every other call (see `iam::grpc_auth`).
pub const REGISTRATION_KEY_METADATA_KEY: &str = "x-aa-registration-key";

/// The outcome of resolving a registration's organization, with the provenance a
/// later re-bind (AAASM-6447) depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOrg {
    /// The authoritative organization to record; `None` for an org-less agent.
    pub org: Option<String>,
    /// `true` only when a validated operator key *bound to* `org` decided it. An
    /// organization merely asserted by an unbound admin key, or no organization at
    /// all, is `false`: neither can authorize taking over an existing agent's
    /// credential.
    pub key_bound: bool,
}

/// Resolves a registration credential to the organization it is bound to.
#[derive(Clone)]
pub struct OrgBinder {
    keys: Arc<ApiKeyStore>,
}

impl OrgBinder {
    /// Build a binder over an operator API key store.
    pub fn new(keys: Arc<ApiKeyStore>) -> Self {
        Self { keys }
    }

    /// Decide the organization of a registration.
    ///
    /// `claimed` is the request's `AgentId.org_id` (empty when absent). Returns
    /// the authoritative organization to record, `None` for an org-less agent.
    pub fn resolve<T>(&self, request: &Request<T>, claimed: &str) -> Result<Option<String>, Status> {
        self.resolve_binding(request, claimed).map(|resolved| resolved.org)
    }

    /// [`resolve`](Self::resolve), also reporting whether the organization came
    /// from a key bound to it (see [`ResolvedOrg::key_bound`]).
    pub fn resolve_binding<T>(&self, request: &Request<T>, claimed: &str) -> Result<ResolvedOrg, Status> {
        let values = request.metadata().get_all(REGISTRATION_KEY_METADATA_KEY);
        let mut it = values.iter();
        let presented = match (it.next(), it.next()) {
            (None, _) => None,
            // A header that is present must be one usable key. Ignoring a garbled
            // or repeated one would turn "a key was sent and it is wrong" into
            // "no key", i.e. an org-less registration the caller did not ask for.
            (Some(v), None) => match v.to_str().map(str::trim) {
                Ok(key) if !key.is_empty() => Some(key),
                _ => return Err(unusable_header()),
            },
            (Some(_), Some(_)) => return Err(unusable_header()),
        };
        self.bind_presented(presented, claimed)
    }

    #[cfg(test)]
    fn resolve_presented(&self, presented: Option<&str>, claimed: &str) -> Result<Option<String>, Status> {
        self.bind_presented(presented, claimed).map(|resolved| resolved.org)
    }

    fn bind_presented(&self, presented: Option<&str>, claimed: &str) -> Result<ResolvedOrg, Status> {
        let unbound = |org: Option<String>| ResolvedOrg { org, key_bound: false };
        let claimed = (!claimed.is_empty()).then_some(claimed);
        let Some(raw) = presented else {
            return match claimed {
                None => Ok(unbound(None)),
                Some(_) => Err(reject(
                    "no_credential",
                    Status::permission_denied(
                        "agent_id.org_id is a claim and needs an organization-bound registration key \
                         (x-aa-registration-key); none was presented",
                    ),
                )),
            };
        };

        let entry = match self.keys.validate_detailed(raw) {
            Ok(entry) => entry,
            Err(KeyNotValid::NotFound | KeyNotValid::Revoked | KeyNotValid::Expired) => {
                return Err(reject(
                    "unauthenticated",
                    Status::unauthenticated("registration key is not valid"),
                ));
            }
        };

        match (entry.org_id.as_deref().filter(|o| !o.is_empty()), claimed) {
            (Some(bound), None) => Ok(ResolvedOrg {
                org: Some(bound.to_owned()),
                key_bound: true,
            }),
            (Some(bound), Some(c)) if bound == c => Ok(ResolvedOrg {
                org: Some(bound.to_owned()),
                key_bound: true,
            }),
            (Some(_), Some(_)) => Err(reject(
                "mismatch",
                Status::permission_denied(
                    "claimed org_id does not match the organization bound to the registration key",
                ),
            )),
            (None, None) => Ok(unbound(None)),
            (None, Some(c)) if entry.scopes.contains(&Scope::Admin) => Ok(unbound(Some(c.to_owned()))),
            (None, Some(_)) => Err(reject(
                "unbound_key",
                Status::permission_denied("the registration key is not bound to an organization and cannot assert one"),
            )),
        }
    }
}

fn unusable_header() -> Status {
    reject(
        "unauthenticated",
        Status::unauthenticated("x-aa-registration-key must be one non-empty ASCII value"),
    )
}

fn reject(reason: &'static str, status: Status) -> Status {
    metrics::counter!(METRIC_REGISTER_ORG_REJECTED, "reason" => reason).increment(1);
    tracing::warn!(reason, "registration refused by the organization binding");
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_auth::api_key::{ApiKey, ApiKeyEntry};

    fn entry(org: Option<&str>, scopes: Vec<Scope>) -> (String, ApiKeyEntry) {
        let key = ApiKey::generate();
        let e = ApiKeyEntry {
            id: uuid::Uuid::new_v4().to_string(),
            key_hash: key.hash().unwrap(),
            scopes,
            created_at: 0,
            expires_at: None,
            label: None,
            team_id: None,
            org_id: org.map(str::to_owned),
            key_lookup: Some(key.lookup()),
        };
        (key.as_str().to_owned(), e)
    }

    fn binder(entries: Vec<ApiKeyEntry>) -> OrgBinder {
        OrgBinder::new(Arc::new(ApiKeyStore::from_entries(entries)))
    }

    #[test]
    fn no_credential_no_claim_is_org_less() {
        assert_eq!(binder(vec![]).resolve_presented(None, "").unwrap(), None);
    }

    #[test]
    fn no_credential_with_claim_is_rejected() {
        let err = binder(vec![]).resolve_presented(None, "acme").unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn invalid_key_is_unauthenticated_even_without_claim() {
        let err = binder(vec![])
            .resolve_presented(Some("aa_00000000000000000000000000000000"), "")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn bound_key_derives_org_and_accepts_matching_claim() {
        let (raw, e) = entry(Some("acme"), vec![Scope::Read]);
        let b = binder(vec![e]);
        assert_eq!(b.resolve_presented(Some(&raw), "").unwrap().as_deref(), Some("acme"));
        assert_eq!(
            b.resolve_presented(Some(&raw), "acme").unwrap().as_deref(),
            Some("acme")
        );
    }

    #[test]
    fn bound_key_rejects_spoofed_org_even_for_admin() {
        let (raw, e) = entry(Some("acme"), vec![Scope::Admin]);
        let err = binder(vec![e]).resolve_presented(Some(&raw), "globex").unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn unbound_admin_may_assert_org_but_unbound_non_admin_may_not() {
        let (admin_raw, admin) = entry(None, vec![Scope::Admin]);
        let (plain_raw, plain) = entry(None, vec![Scope::Read]);
        let b = binder(vec![admin, plain]);
        assert_eq!(
            b.resolve_presented(Some(&admin_raw), "acme").unwrap().as_deref(),
            Some("acme")
        );
        assert_eq!(
            b.resolve_presented(Some(&plain_raw), "acme").unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(b.resolve_presented(Some(&plain_raw), "").unwrap(), None);
    }

    #[test]
    fn expired_and_revoked_keys_are_unauthenticated() {
        let (raw_e, mut expired) = entry(Some("acme"), vec![Scope::Read]);
        expired.expires_at = Some(1);
        let (raw_r, revoked) = entry(Some("acme"), vec![Scope::Read]);
        let store = ApiKeyStore::from_entries(vec![expired, revoked.clone()]);
        store.revoke(&revoked.id);
        let b = OrgBinder::new(Arc::new(store));
        for raw in [raw_e, raw_r] {
            assert_eq!(
                b.resolve_presented(Some(&raw), "acme").unwrap_err().code(),
                tonic::Code::Unauthenticated
            );
        }
    }

    fn request_with(values: &[&[u8]]) -> Request<()> {
        let mut req = Request::new(());
        for v in values {
            let value = tonic::metadata::MetadataValue::<tonic::metadata::Ascii>::try_from(*v).expect("header bytes");
            req.metadata_mut().append(REGISTRATION_KEY_METADATA_KEY, value);
        }
        req
    }

    #[test]
    fn header_is_trimmed_and_resolved() {
        let (raw, e) = entry(Some("acme"), vec![Scope::Read]);
        let b = binder(vec![e]);
        let padded = format!("  {raw} ");
        let req = request_with(&[padded.as_bytes()]);
        assert_eq!(b.resolve(&req, "").unwrap().as_deref(), Some("acme"));
    }

    #[test]
    fn absent_header_is_the_org_less_path() {
        assert_eq!(binder(vec![]).resolve(&request_with(&[]), "").unwrap(), None);
    }

    #[test]
    fn blank_non_ascii_or_repeated_headers_are_unauthenticated_not_ignored() {
        let (raw, e) = entry(Some("acme"), vec![Scope::Read]);
        let b = binder(vec![e]);
        for bad in [
            request_with(&[b"   "]),
            request_with(&[&[0xC3, 0xA9][..]]),
            request_with(&[raw.as_bytes(), raw.as_bytes()]),
        ] {
            assert_eq!(b.resolve(&bad, "").unwrap_err().code(), tonic::Code::Unauthenticated);
        }
    }

    #[test]
    fn only_a_key_bound_to_the_org_marks_the_binding_as_key_bound() {
        let (bound_raw, bound) = entry(Some("acme"), vec![Scope::Read]);
        let (admin_raw, admin) = entry(None, vec![Scope::Admin]);
        let b = binder(vec![bound, admin]);

        let resolved = b.bind_presented(Some(&bound_raw), "").unwrap();
        assert_eq!((resolved.org.as_deref(), resolved.key_bound), (Some("acme"), true));
        let resolved = b.bind_presented(Some(&bound_raw), "acme").unwrap();
        assert_eq!((resolved.org.as_deref(), resolved.key_bound), (Some("acme"), true));

        let asserted = b.bind_presented(Some(&admin_raw), "acme").unwrap();
        assert_eq!((asserted.org.as_deref(), asserted.key_bound), (Some("acme"), false));
        let none = b.bind_presented(None, "").unwrap();
        assert_eq!((none.org, none.key_bound), (None, false));
    }
}
