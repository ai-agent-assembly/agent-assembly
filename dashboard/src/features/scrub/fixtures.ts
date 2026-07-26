/**
 * The editable sample payload for the in-page redaction preview.
 *
 * This is the one thing on the Scrub surface that is legitimately a fixture: it
 * is *input* the operator types over, not a measurement the page reports. It is
 * illustrative and labelled as such by `PayloadDiff`.
 *
 * The detector catalogue that used to live here has moved to `detectors.ts` and
 * is now derived from `aa-security/src/scanner.rs` (AAASM-5156). Nothing in this
 * file feeds a counter, a posture, or a coverage claim.
 *
 * Every credential-shaped literal below is a documentation placeholder chosen to
 * trip a *real* detector prefix — no value here is, or has ever been, live.
 */
export const SAMPLE_PAYLOAD = `Hi team — quick note from research-bot-04 sync.

Connecting with AKIAIOSFODNN7EXAMPLE and pulling the mirror from
postgres://svc:pw@warehouse.example/analytics using ghp_EXAMPLEEXAMPLEEXAMPLEEX.

Found one customer record:
  name:  Jane Doe
  email: jane.doe@acme.com
  ssn:   123-45-6789
  card:  4111 1111 1111 1111

Deploy key below:
-----BEGIN RSA PRIVATE KEY-----

Forwarding to support@external-vendor.io for follow-up.`
