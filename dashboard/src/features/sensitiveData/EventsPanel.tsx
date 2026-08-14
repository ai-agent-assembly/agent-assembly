/**
 * The drill-down from an aggregate to privacy-safe event detail (AAASM-5360).
 *
 * ## What is on screen, and what cannot be
 *
 * ADR 0032 §9 confines byte offsets to the tamper-evident tier. The API returns
 * no offset, no length and no raw value; `schema.ts` names every field the page
 * may read, so one arriving on the wire is stripped before a component sees it;
 * and nothing here derives a position from anything. The drill-down granularity
 * §9 grants instead is the inspected **field path** — a name, not a value — and
 * the `[REDACTED:…]` **label** each finding redacts to, which is likewise a
 * label and not the thing it replaced.
 *
 * ## `total` is not the page
 *
 * `SensitiveDataEventsResponse.total` is every matching event in the window; the
 * `events` array is a page of at most `limit`. The API's own doc says a UI
 * pairing the two must label which is which, so the count above the table is a
 * sentence rather than a number, and it says what is *not* on the page.
 *
 * ## A row's prevention flag is a boolean with three meanings
 *
 * See `eventReading.ts`: `prevented_transmission: false` covers both "evidence
 * was recorded and the conditions did not hold" and "nothing was recorded, so
 * they could not have". Rendering the boolean directly would print a column of
 * ✗ marks describing a product that fails to prevent things, for a product that
 * does not measure whether it does.
 */
import { isKnown, type Certain } from '../../lib/truthfulness'
import { StatusState } from '../../components/truthfulness'
import { CountFigure } from './CountFigure'
import { formatInstantNs } from './format'
import { readEventInspection, readEventPrevention, transformationSentence } from './eventReading'
import {
  pageCoverageSentence,
  readPageCoverage,
  readResult,
  resultDescription,
  resultTitle,
} from './measures'
import type { SensitiveDataEventsResponse } from './schema'
import './sensitiveData.css'

export interface EventsPanelProps {
  readonly events: Certain<SensitiveDataEventsResponse>
  readonly activeFilterCount: number
  readonly selectedEventId: string | null
  readonly onSelectEvent: (eventId: string) => void
}

export function EventsPanel({
  events,
  activeFilterCount,
  selectedEventId,
  onSelectEvent,
}: Readonly<EventsPanelProps>) {
  if (!isKnown(events)) {
    return (
      <section className="sd-panel" data-testid="sd-events">
        <StatusState
          state={events.state}
          title="The event list could not be read"
          description="No rows are shown. An empty table would read as “no action carried sensitive data”."
          detail={events.detail}
          testId="sd-events-absent"
        />
      </section>
    )
  }

  const { events: rows, total } = events.value
  const coverage = readPageCoverage(rows.length, total)

  return (
    <section className="sd-panel" data-testid="sd-events">
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">Actions</h2>
      </div>

      {rows.length === 0 ? (
        <StatusState
          state={null}
          title={resultTitle(readResult(0, activeFilterCount))}
          description={resultDescription(readResult(0, activeFilterCount))}
          testId="sd-events-empty"
        />
      ) : (
        <>
          <p
            className="sd-coverage"
            data-testid="sd-events-coverage"
            data-truncated={coverage.truncated ? 'true' : 'false'}
          >
            {pageCoverageSentence(coverage)}
          </p>
          <div className="sd-table__scroll">
            <table className="sd-table" data-testid="sd-events-table">
              <thead>
                <tr>
                  <th scope="col">When (UTC)</th>
                  <th scope="col">Acting agent</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Findings carried</th>
                  <th scope="col">Transmission</th>
                  <th scope="col">Inspection</th>
                  <th scope="col">
                    <span className="sd-sr-only">Detail</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((event) => {
                  const prevention = readEventPrevention(event)
                  const inspection = readEventInspection(event)
                  return (
                    <tr
                      key={event.event_id}
                      data-testid={`sd-event-row-${event.event_id}`}
                      aria-selected={event.event_id === selectedEventId}
                    >
                      <td>{formatInstantNs(event.occurred_at_ns)}</td>
                      <td>{event.acting_agent_id}</td>
                      <td>
                        {event.destination_id}{' '}
                        <span className="sd-figure__unit">({event.destination_kind})</span>
                      </td>
                      <td>{event.verdict}</td>
                      <td className="sd-num">
                        <CountFigure
                          measure={{
                            id: 'finding_count',
                            label: 'Findings carried',
                            unit: 'finding',
                            value: event.finding_count,
                            description: transformationSentence(event),
                          }}
                          inline
                          testId={`sd-event-findings-${event.event_id}`}
                        />
                      </td>
                      <td
                        data-testid={`sd-event-prevention-${event.event_id}`}
                        data-prevention={prevention.kind}
                        title={prevention.explanation}
                      >
                        {prevention.label}
                      </td>
                      <td
                        data-testid={`sd-event-inspection-${event.event_id}`}
                        data-complete={inspection.complete ? 'true' : 'false'}
                        title={inspection.explanation}
                      >
                        {inspection.label}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="sd-row-button"
                          data-testid={`sd-event-open-${event.event_id}`}
                          onClick={() => onSelectEvent(event.event_id)}
                        >
                          Detail
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  )
}
