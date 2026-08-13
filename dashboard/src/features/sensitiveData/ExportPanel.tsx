/**
 * The compliance export, behind a deliberate act (AAASM-5360).
 *
 * ## Why the acknowledgement is a control and not a constant
 *
 * `GET /api/v1/sensitive-data/export` requires `Scope::Admin` **and** an
 * explicit `acknowledge_export=true`. The scope says *who may*; the
 * acknowledgement says *this one, on purpose*. The API's own doc gives the
 * reason: the export releases a tenant's whole governance record and is written
 * to an access log naming the principal, "so it is not something a caller
 * performs by navigating to a URL".
 *
 * A UI that set `acknowledge_export=true` in a link's query string, or defaulted
 * it in a client, would remove exactly the property the parameter exists for —
 * a followed link would release the record and log somebody's name against it.
 * So:
 *
 *  - the checkbox starts **unchecked** on every mount, and is never persisted;
 *  - the button is **disabled** until it is ticked;
 *  - nothing is fetched on mount, on focus, or on a filter change — there is no
 *    `useQuery` for this route anywhere in the feature;
 *  - the acknowledgement is passed through as the operator set it
 *    (`requestComplianceExport` takes it as a required argument, so it cannot be
 *    defaulted by omission).
 *
 * ## What a refusal looks like
 *
 * A non-admin gets a `403`. That is rendered as a refusal with its own copy, not
 * as an empty download or a generic error: "you may not do this" and "this
 * failed" are different facts and lead the operator to different next steps.
 */
import { useState } from 'react'
import { StatusState } from '../../components/truthfulness'
import {
  SensitiveDataHttpError,
  accessDescription,
  accessTitle,
  readAccess,
  requestComplianceExport,
} from './api'
import type { SensitiveDataFilters } from './filters'
import { formatWindow } from './format'
import { formatCount } from './measures'
import { decodeExportAccessRecord } from './schema'
import './sensitiveData.css'

type ExportState =
  | { readonly phase: 'idle' }
  | { readonly phase: 'running' }
  | { readonly phase: 'done'; readonly summary: string }
  | { readonly phase: 'refused'; readonly error: unknown }

export interface ExportPanelProps {
  readonly filters: SensitiveDataFilters
}

export function ExportPanel({ filters }: Readonly<ExportPanelProps>) {
  // Not lifted to the page and not persisted in the URL: an acknowledgement
  // that survives a reload or a shared link is not an acknowledgement.
  const [acknowledged, setAcknowledged] = useState(false)
  const [state, setState] = useState<ExportState>({ phase: 'idle' })

  const run = async () => {
    setState({ phase: 'running' })
    try {
      const body = await requestComplianceExport(filters, acknowledged)
      setState({ phase: 'done', summary: describeExport(body) })
    } catch (error) {
      setState({ phase: 'refused', error })
    }
  }

  return (
    <section className="sd-panel" data-testid="sd-export">
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">Compliance export</h2>
      </div>
      <p className="sd-panel__note">
        Exports every matching action and its findings for the current filters. It requires
        administrator scope, and the gateway writes an access record naming you before it produces
        the body — a record it will refuse the export rather than skip.
      </p>

      <label className="sd-export__ack">
        <input
          type="checkbox"
          data-testid="sd-export-ack"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>
          I am deliberately releasing this organisation’s sensitive-data record, and I understand
          this export is logged against my account.
        </span>
      </label>

      <button
        type="button"
        className="sd-button sd-button--primary"
        data-testid="sd-export-run"
        disabled={!acknowledged || state.phase === 'running'}
        onClick={() => {
          void run()
        }}
      >
        {state.phase === 'running' ? 'Exporting…' : 'Export'}
      </button>

      {state.phase === 'done' && (
        <p className="sd-export__result" data-testid="sd-export-result" role="status">
          {state.summary}
        </p>
      )}

      {state.phase === 'refused' && (
        <div data-testid="sd-export-refused">
          <StatusState
            state={
              state.error instanceof SensitiveDataHttpError && state.error.status === 403
                ? 'not-supported'
                : 'unavailable'
            }
            title={accessTitle(readAccess({ isError: true, error: state.error }))}
            description={accessDescription(readAccess({ isError: true, error: state.error }))}
            testId="sd-export-refused-state"
          />
        </div>
      )}
    </section>
  )
}

/**
 * What was released, in the operator's terms.
 *
 * The body's own `access_record` is the authority for the counts, not the
 * lengths of the arrays beside it: the record is what the gateway wrote to the
 * access log, and a summary that disagreed with the audit trail would be worse
 * than no summary. Anything unreadable is reported as unreadable rather than
 * summarised optimistically.
 */
function describeExport(body: unknown): string {
  const decoded = decodeExportAccessRecord(body)
  if (!decoded.ok) {
    return `The export completed, but its access record could not be read, so what was released cannot be stated here — check the gateway’s export access log. (${decoded.reason})`
  }
  const record = decoded.value.access_record
  return `Exported ${formatCount(record.event_count)} actions and ${formatCount(
    record.finding_count,
  )} findings over ${formatWindow(record.from_ns, record.to_ns)}, recorded against ${
    record.principal
  }.`
}
