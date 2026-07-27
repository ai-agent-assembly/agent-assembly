import type { ReactNode } from 'react'
import { Drawer } from '../Drawer'
import { ApprovalActions } from '../../features/approvals/ApprovalActions'
import { ApprovalCountdown } from '../../features/approvals/ApprovalCountdown'
import type { Approval } from '../../features/approvals/api'
import type { Verdict } from '../../features/trace/decision'
import { absent, isKnown, known, type Certain } from '../../lib/truthfulness'
import { AbsenceMarker } from '../truthfulness'
import { VerdictChip } from './VerdictChip'
import './ApprovalDetailDrawer.css'

export interface ApprovalDetailDrawerProps {
  /** The approval under review. `null` renders nothing (drawer closed). */
  readonly approval: Approval | null
  /** Fires on ESC / scrim / close-button — the caller unmounts by clearing `approval`. */
  readonly onClose: () => void
  /** Actor identity forwarded to the approve / reject mutations. */
  readonly by?: string
  /** Fires after the approve mutation resolves — caller closes / refreshes. */
  readonly onApproved?: (id: string) => void
  /** Fires after the reject mutation resolves, with the reason entered. */
  readonly onRejected?: (id: string, reason: string) => void
  /** Fires if either mutation rejects; caller owns toast / restore. */
  readonly onError?: (action: 'approve' | 'reject', error: unknown) => void
  /**
   * Trailing action-slot forwarded to `ApprovalActions.extraActions`. This is the
   * deliberate seam for the backend-blocked affordances — approve-with-conditions,
   * forward, and quorum (AAASM-5095). Those are NOT built here: rendering the
   * conditions form / forward button / approver roster would fabricate data the
   * gateway does not yet emit. Callers slot future controls here once 5095 lands.
   */
  readonly extraActions?: ReactNode
}

/**
 * Approval lifecycle status → the verdict chip shown in the head.
 *
 * The three statuses `ApprovalResponse.status` documents in `openapi/v1.yaml`
 * ("pending", "approved", or "rejected") and nothing else — the field is typed
 * as a bare string with no enum, so the wire may carry a fourth value this
 * build has never heard of.
 *
 * A `Map`, not an object literal, for the same reason as
 * `features/trace/decision.ts` (AAASM-5109): the key arrives over the wire, and
 * a plain-object lookup resolves the prototype chain — `status: "constructor"`
 * returns `Object`, which is `!== undefined`, so a `??` guard never fires and a
 * *function* is handed on as a verdict. A `Map` has no inherited keys.
 */
const VERDICT_BY_STATUS = new Map<string, Verdict>([
  ['pending', 'pending'],
  ['approved', 'allowed'],
  ['rejected', 'denied'],
])

/**
 * The head verdict for an approval, or an explicit absence.
 *
 * There is deliberately no default. The previous `?? 'pending'` claimed of any
 * unrecognised status that the approval is still awaiting a human — a positive
 * statement about the governance queue that nothing established, and one that
 * renders *identically* to a genuinely pending request, so an operator has no
 * way to tell the two apart. (The footer is unaffected: it gates on
 * `status !== 'pending'` directly, so an uninterpretable status already
 * disables the decision buttons, which is the fail-closed direction.)
 *
 * `unknown` is the honest state here, not `unavailable` (the request succeeded
 * and carried a status), not `not-evaluated` (a status exists, so something
 * did evaluate this approval — we simply cannot read its answer), and not
 * `not-supported` (the backend does supply the field). We asked, we got a
 * value, and we could not determine what it means.
 *
 * Matching is exact rather than case-folded: the gateway is the sole producer
 * of this field and emits the three documented lowercase words, so treating
 * some other casing as equivalent would be an interpretation the schema does
 * not authorise.
 */
function statusVerdict(status: string): Certain<Verdict> {
  const named = VERDICT_BY_STATUS.get(status)
  if (named !== undefined) return known(named)
  return absent<Verdict>('unknown', `Unrecognised approval status "${status}"`)
}

/**
 * The head chip — or the absence marker when the status cannot be interpreted.
 *
 * The chip is the drawer's loudest claim about an approval, so an unreadable
 * status renders the neutral `—` affordance (with its screen-reader sentence
 * and hover detail) rather than a coloured verdict. This mirrors how
 * `DecisionExplainer` treats an underivable trace verdict.
 */
function HeadVerdict({ status }: Readonly<{ status: string }>) {
  const verdict = statusVerdict(status)
  if (isKnown(verdict)) {
    return <VerdictChip verdict={verdict.value} shape="square" />
  }
  return (
    <AbsenceMarker
      state={verdict.state}
      detail={verdict.detail}
      showLabel
      testId="approval-detail-verdict-absent"
    />
  )
}

interface KvRow {
  readonly label: string
  readonly value: ReactNode
}

function buildRows(approval: Approval): KvRow[] {
  const rows: KvRow[] = [
    { label: 'agent', value: <code>{approval.agent_id}</code> },
    { label: 'action', value: approval.action },
    { label: 'reason', value: approval.reason },
    { label: 'requested', value: <code>{approval.created_at}</code> },
  ]
  // `team_id` is optional on the API response — only shown when routed to a team.
  if (approval.team_id) {
    rows.push({ label: 'team', value: <code>{approval.team_id}</code> })
  }
  return rows
}

/**
 * Trace approval-review drawer — the approval variant of the Trace surface
 * (AAASM-5075). Composes the shared Wave-2 primitives rather than re-implementing
 * them: the foundation `Drawer` shell, `ApprovalCountdown` as the SLA timer
 * (driven off `expires_at`), a request-detail KV built only from fields the
 * `ApprovalResponse` actually carries, and the shared `ApprovalActions` footer
 * wired to the live approve / reject mutations.
 *
 * Deliberately truthful about what the backend emits: it does NOT render a
 * per-layer decision trace, an approver quorum roster, or forward / conditions
 * controls — those are backend-blocked (AAASM-5095) and would fabricate data.
 * The single seam for them is `extraActions`, forwarded untouched to
 * `ApprovalActions`.
 */
export function ApprovalDetailDrawer({
  approval,
  onClose,
  by,
  onApproved,
  onRejected,
  onError,
  extraActions,
}: Readonly<ApprovalDetailDrawerProps>) {
  const open = approval !== null

  return (
    <Drawer open={open} onClose={onClose} ariaLabel="Approval detail">
      {approval && (
        <div className="approval-detail" data-testid="approval-detail-drawer">
          <header className="approval-detail__head">
            <div className="approval-detail__head-main">
              <div className="approval-detail__title-row">
                <span className="approval-detail__id" data-testid="approval-detail-id">
                  {approval.id}
                </span>
                <HeadVerdict status={approval.status} />
              </div>
              <div className="approval-detail__summary">
                <code>{approval.agent_id}</code> · {approval.action}
              </div>
            </div>
            <button
              type="button"
              className="approval-detail__close"
              data-testid="approval-detail-close"
              aria-label="Close approval detail"
              onClick={onClose}
            >
              ✕
            </button>
          </header>

          <div className="approval-detail__body" data-testid="approval-detail-body">
            {/* SLA — only meaningful while pending; `expires_at` is empty post-decision. */}
            {approval.status === 'pending' && approval.expires_at && (
              <section className="approval-detail__section" data-testid="approval-detail-sla">
                <div className="approval-detail__section-head">
                  <span className="approval-detail__section-title">SLA</span>
                  <ApprovalCountdown expiresAt={approval.expires_at} />
                </div>
              </section>
            )}

            <section className="approval-detail__section">
              <div className="approval-detail__section-title">request detail</div>
              <dl className="approval-detail__kv">
                {buildRows(approval).map((row) => (
                  <div className="approval-detail__kv-row" key={row.label}>
                    <dt className="approval-detail__kv-k">{row.label}</dt>
                    <dd className="approval-detail__kv-v">{row.value}</dd>
                  </div>
                ))}
              </dl>
            </section>
          </div>

          <footer className="approval-detail__foot" data-testid="approval-detail-foot">
            <ApprovalActions
              approvalId={approval.id}
              by={by}
              size="md"
              disabled={approval.status !== 'pending'}
              onApproved={onApproved}
              onRejected={onRejected}
              onError={onError}
              extraActions={extraActions}
            />
          </footer>
        </div>
      )}
    </Drawer>
  )
}
