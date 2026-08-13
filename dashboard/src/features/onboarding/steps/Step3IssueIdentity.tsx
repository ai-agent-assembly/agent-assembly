/**
 * Step 3 — agent identity (AAASM-5179).
 *
 * This step used to mint a DID in the browser: 16 random bytes behind
 * `did:aa:`, a hardcoded `alg: 'Ed25519'`, a "fingerprint" of 8 further
 * unrelated random bytes, and the line *"private key stored in your
 * `~/.aa/keys/` · do not commit"*. No keypair was ever generated — there is no
 * `crypto.subtle` call anywhere in the dashboard — and a browser cannot write
 * to that path. It was a security instruction premised on a fiction: an
 * operator who believes a private key is on disk skips real key provisioning.
 *
 * Identity is issued by the gateway over the runtime gRPC handshake
 * (`RequestChallenge` / `Register`, with an Ed25519 possession proof). There is
 * no HTTP surface for it — `openapi/v1.yaml` declares `GET /api/v1/agents` only,
 * and AAASM-5176 owns adding one. Until a *persistence-verification signal*
 * exists, this step may not claim a key was generated, signed, published, or
 * stored, so it renders `not-supported` and offers no action at all.
 */
import { StatusState } from '../../../components/truthfulness'
import './Steps.css'

export function Step3IssueIdentity() {
  return (
    <section data-testid="onboarding-step-identity">
      <h2 className="onb-body-title">Issue first agent identity.</h2>
      <p className="onb-body-sub">
        Agent identity is minted by the gateway when your agent registers. The
        dashboard has no path to it, so nothing on this page can issue one for
        you.
      </p>

      <StatusState
        state="not-supported"
        title="Identity issuance is not available from the dashboard"
        description={
          <>
            Your agent obtains its DID during the SDK&rsquo;s registration
            handshake with the gateway, which requires a keypair the SDK holds
            and a possession proof this page cannot produce. There is no HTTP
            endpoint to call, so this step cannot generate a keypair, and no key
            material is created, transmitted, or written to disk by the browser.
          </>
        }
        detail="Run your agent with the SDK installed — step 5 reports the registry state once it registers."
        testId="onboarding-identity-unsupported"
      />
    </section>
  )
}
