/**
 * One action, its evidence columns, and its findings (AAASM-5360).
 *
 * ## The privacy contract, restated where it is easiest to break
 *
 * This is the deepest view the product offers, and it is still built entirely
 * from names and labels:
 *
 *  - `field_path` is the **name** of the inspected field. ADR 0032 §9 grants it
 *    *in place of* a byte offset, and there is no offset or length on the wire
 *    to render even if someone wanted one.
 *  - `redaction_label` is the `[REDACTED:…]` marker substituted for the value,
 *    not the value.
 *  - `category`, `severity`, `confidence`, `method`, `status` and `recognizer`
 *    describe the finding, never its content.
 *
 * Nothing here concatenates, slices or positions anything, so no rendering here
 * can reconstruct a location the API declined to give.
 *
 * ## Three evidence columns, shown as evidence
 *
 * `enforcement_point`, `transmission_evidence` and `enforcement_mode` are ADR
 * 0032 §8's prevention conditions 1, 3 and 4. They are rendered as their own
 * labelled fields *next to* the derived verdict, so a reader can see why the
 * verdict is what it is rather than being asked to trust it — and, on this
 * build, can see that `transmission_evidence` is `not_recorded` for every row.
 *
 * ## `status` never means "clean"
 *
 * Nothing in the triage vocabulary means the finding was a false positive that
 * can be ignored, and the panel does not add a reading that implies one.
 */
import { isKnown, type Certain } from '../../lib/truthfulness'
import { StatusState } from '../../components/truthfulness'
import { formatInstantNsPrecise } from './format'
import { readEventInspection, readEventPrevention, transformationSentence } from './eventReading'
import type { SensitiveDataEventDetailResponse } from './schema'
import './sensitiveData.css'

export interface EventDetailPanelProps {
  readonly detail: Certain<SensitiveDataEventDetailResponse>
  readonly onClose: () => void
}

function Field({ term, value }: Readonly<{ term: string; value: string }>) {
  return (
    <div>
      <div className="sd-detail__term">{term}</div>
      <div className="sd-detail__value">{value}</div>
    </div>
  )
}

export function EventDetailPanel({ detail, onClose }: Readonly<EventDetailPanelProps>) {
  return (
    <section className="sd-panel" data-testid="sd-event-detail" aria-label="Action detail">
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">Action detail</h2>
        <button
          type="button"
          className="sd-button"
          data-testid="sd-event-detail-close"
          onClick={onClose}
        >
          Close
        </button>
      </div>

      {!isKnown(detail) ? (
        <StatusState
          state={detail.state}
          title="This action could not be read"
          description="The gateway did not return a readable detail for it. Nothing is inferred from the row that opened this panel."
          detail={detail.detail}
          testId="sd-event-detail-absent"
        />
      ) : (
        <EventDetailBody detail={detail.value} />
      )}
    </section>
  )
}

function EventDetailBody({ detail }: Readonly<{ detail: SensitiveDataEventDetailResponse }>) {
  const { event, findings } = detail
  const prevention = readEventPrevention(event)
  const inspection = readEventInspection(event)

  return (
    <>
      <div className="sd-detail__grid" data-testid="sd-event-detail-fields">
        <Field term="Action" value={event.event_id} />
        <Field term="When (UTC)" value={formatInstantNsPrecise(event.occurred_at_ns)} />
        <Field term="Acting agent" value={event.acting_agent_id} />
        <Field
          term="Delegation"
          value={`root ${event.root_agent_id}${
            event.parent_agent_id ? `, via ${event.parent_agent_id}` : ''
          }, depth ${event.delegation_depth}`}
        />
        <Field term="Team" value={event.team_id ?? 'not attributed'} />
        <Field term="Operation" value={event.operation} />
        <Field
          term="Destination"
          value={`${event.destination_id} (${event.destination_kind}, ${event.trust_zone}, ${event.direction})`}
        />
        <Field term="Outcome" value={event.verdict} />
        <Field term="Policy document" value={event.policy_document_id ?? 'not attributed'} />
        <Field
          term="Matched rules"
          value={event.matched_rule_ids.length > 0 ? event.matched_rule_ids.join(', ') : 'none'}
        />
        <Field
          term="Reason codes"
          value={event.reason_codes.length > 0 ? event.reason_codes.join(', ') : 'none'}
        />
        <Field term="Session" value={event.session_id ?? 'not recorded'} />
        <Field term="Trace" value={event.trace_id ?? 'not recorded'} />
        <Field
          term="Inspected fields"
          value={
            event.inspected_field_paths.length > 0
              ? event.inspected_field_paths.join(', ')
              : 'none recorded'
          }
        />
      </div>

      <h3 className="sd-panel__title">Prevention evidence</h3>
      <div className="sd-detail__grid" data-testid="sd-event-detail-evidence">
        {/* §8 conditions 1, 3 and 4, shown so the derived verdict can be checked
            rather than taken on trust. */}
        <Field term="Enforcement point (condition 1)" value={event.enforcement_point} />
        <Field term="Transmission evidence (condition 3)" value={event.transmission_evidence} />
        <Field term="Enforcement mode (condition 4)" value={event.enforcement_mode} />
      </div>
      <p
        className="sd-prevention__qualifier"
        data-testid="sd-event-detail-prevention"
        data-prevention={prevention.kind}
      >
        <strong>{prevention.label}.</strong> {prevention.explanation}
      </p>

      <p
        className={inspection.complete ? 'sd-coverage' : 'sd-coverage sd-coverage--incomplete'}
        data-testid="sd-event-detail-inspection"
        data-complete={inspection.complete ? 'true' : 'false'}
      >
        {inspection.explanation}
      </p>

      <p className="sd-panel__note" data-testid="sd-event-detail-transformations">
        {transformationSentence(event)}
      </p>

      <div className="sd-table__scroll">
        <table className="sd-table" data-testid="sd-event-detail-findings">
          <caption className="sd-panel__note">
            Each finding is described by what it is and where it was found — a field name and the
            label it redacts to. No offset, no length and no detected value is returned by the API
            or rendered here.
          </caption>
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Category</th>
              <th scope="col">Severity</th>
              <th scope="col">Confidence</th>
              <th scope="col">Detection method</th>
              <th scope="col">Triage status</th>
              <th scope="col">Recognizer</th>
              <th scope="col">Field path</th>
              <th scope="col">Redaction label</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr
                key={finding.finding_ordinal}
                data-testid={`sd-finding-row-${finding.finding_ordinal}`}
              >
                <td className="sd-num">{finding.finding_ordinal}</td>
                <td>{finding.category}</td>
                <td>{finding.severity}</td>
                <td>{finding.confidence}</td>
                <td>{finding.method}</td>
                <td>{finding.status}</td>
                <td>
                  {finding.recognizer}{' '}
                  <span className="sd-figure__unit">{finding.recognizer_version}</span>
                </td>
                <td>{finding.field_path}</td>
                <td>{finding.redaction_label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
