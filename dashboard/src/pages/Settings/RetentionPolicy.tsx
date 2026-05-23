// Settings → Storage → Retention Policy page (AAASM-1592 S-K).
//
// Implements the layout in the parent story description:
//   * Hot tier / Warm tier number inputs
//   * Cold tier action dropdown (Drop / Archive)
//   * Archive URL input (shown only when cold action = Archive)
//   * Save Changes / Run Now (Dry Run) / Run Now action buttons
//   * Last retention run summary panel
//
// Client-side validation runs synchronously on every render; the
// server-side validation in aa-api enforces the same rules so a stale
// client cannot bypass them.

import { useEffect, useMemo, useState } from 'react'
import {
  retentionPolicyClient,
  type ColdActionDto,
  type RetentionPolicyDocument,
  type RetentionRunStatsDto,
  type UpdateRetentionPolicyRequest,
} from '../../api/retention'

interface FormErrors {
  hot_days?: string
  warm_days?: string
  archive_url?: string
}

function validate(req: UpdateRetentionPolicyRequest): FormErrors {
  const errors: FormErrors = {}
  if (!Number.isFinite(req.hot_days) || req.hot_days < 1) {
    errors.hot_days = 'hot_days must be ≥ 1'
  }
  if (!Number.isFinite(req.warm_days) || req.warm_days <= req.hot_days) {
    errors.warm_days = 'warm_days must be strictly greater than hot_days'
  }
  if (req.cold_action === 'archive') {
    const url = (req.archive_url ?? '').trim()
    if (!url) {
      errors.archive_url = 'archive_url is required when cold_action is "archive"'
    } else if (!/^s3:\/\//.test(url) && !/^gs:\/\//.test(url)) {
      errors.archive_url = 'archive_url must start with s3:// or gs://'
    }
  }
  return errors
}

function docToFormState(doc: RetentionPolicyDocument): UpdateRetentionPolicyRequest {
  return {
    hot_days: doc.hot_days,
    warm_days: doc.warm_days,
    cold_action: doc.cold_action,
    archive_url: doc.archive_url ?? '',
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

interface RetentionPolicyPageProps {
  /** Test seam — defaults to the live `retentionPolicyClient`. */
  client?: typeof retentionPolicyClient
}

export function RetentionPolicyPage({ client = retentionPolicyClient }: RetentionPolicyPageProps = {}) {
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [doc, setDoc] = useState<RetentionPolicyDocument | null>(null)
  const [form, setForm] = useState<UpdateRetentionPolicyRequest | null>(null)
  const [saving, setSaving] = useState(false)
  const [running, setRunning] = useState(false)
  const [statusMsg, setStatusMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null)
  const [lastRun, setLastRun] = useState<RetentionRunStatsDto | null>(null)

  // Initial load
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    client
      .get()
      .then((d) => {
        if (cancelled) return
        setDoc(d)
        setForm(docToFormState(d))
        setLastRun(d.last_run ?? null)
        setLoadError(null)
      })
      .catch((e: unknown) => {
        if (cancelled) return
        setLoadError(String(e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [client])

  const errors = useMemo(() => (form ? validate(form) : {}), [form])
  const hasErrors = Object.keys(errors).length > 0

  function updateField<K extends keyof UpdateRetentionPolicyRequest>(
    key: K,
    value: UpdateRetentionPolicyRequest[K],
  ) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev))
    setStatusMsg(null)
  }

  async function handleSave() {
    if (!form || hasErrors) return
    setSaving(true)
    setStatusMsg(null)
    try {
      const body: UpdateRetentionPolicyRequest = {
        hot_days: form.hot_days,
        warm_days: form.warm_days,
        cold_action: form.cold_action,
        archive_url: form.cold_action === 'archive' ? (form.archive_url ?? '').trim() : null,
      }
      const updated = await client.update(body)
      setDoc(updated)
      setForm(docToFormState(updated))
      setLastRun(updated.last_run ?? null)
      setStatusMsg({ kind: 'success', text: 'Retention policy updated.' })
    } catch (e: unknown) {
      setStatusMsg({ kind: 'error', text: `Save failed: ${String(e)}` })
    } finally {
      setSaving(false)
    }
  }

  async function handleRun(dryRun: boolean) {
    setRunning(true)
    setStatusMsg(null)
    try {
      const stats = await client.run(dryRun)
      setLastRun(stats)
      setStatusMsg({
        kind: 'success',
        text: dryRun ? 'Dry run complete.' : 'Retention run complete.',
      })
    } catch (e: unknown) {
      setStatusMsg({ kind: 'error', text: `Run failed: ${String(e)}` })
    } finally {
      setRunning(false)
    }
  }

  if (loading) {
    return (
      <section className="retention-policy" data-testid="retention-policy-page">
        <h1>Retention Policy</h1>
        <div className="retention-policy__loading" data-testid="retention-policy-loading">
          Loading current retention policy…
        </div>
      </section>
    )
  }

  if (loadError || !form || !doc) {
    return (
      <section className="retention-policy" data-testid="retention-policy-page">
        <h1>Retention Policy</h1>
        <div
          className="retention-policy__status retention-policy__status--error"
          data-testid="retention-policy-load-error"
        >
          Could not load retention policy: {loadError ?? 'unknown error'}
        </div>
      </section>
    )
  }

  return (
    <section className="retention-policy" data-testid="retention-policy-page">
      <h1>Retention Policy</h1>
      <p>
        Audit and metric rows are partitioned into <strong>hot</strong>, <strong>warm</strong>, and <strong>cold</strong>{' '}
        tiers. Hot rows stay indexed for fast queries; warm rows are compressed where the backend supports it; cold rows
        are dropped or archived to an object store. Changes apply immediately — the gateway does not need a restart.
      </p>

      <div className="retention-policy__field">
        <label htmlFor="hot_days" className="retention-policy__field-label">
          Hot tier (days)
        </label>
        <p className="retention-policy__field-help">Fully indexed, fast queries.</p>
        <input
          id="hot_days"
          name="hot_days"
          type="number"
          min={1}
          className={`retention-policy__input${errors.hot_days ? ' retention-policy__input--error' : ''}`}
          value={form.hot_days}
          onChange={(e) => updateField('hot_days', Number(e.target.value))}
          data-testid="retention-policy-hot-days"
          aria-invalid={Boolean(errors.hot_days)}
        />
        {errors.hot_days && (
          <div className="retention-policy__field-error" data-testid="retention-policy-hot-days-error">
            {errors.hot_days}
          </div>
        )}
      </div>

      <div className="retention-policy__field">
        <label htmlFor="warm_days" className="retention-policy__field-label">
          Warm tier (days)
        </label>
        <p className="retention-policy__field-help">Compressed, slower queries. Must be greater than hot tier.</p>
        <input
          id="warm_days"
          name="warm_days"
          type="number"
          min={1}
          className={`retention-policy__input${errors.warm_days ? ' retention-policy__input--error' : ''}`}
          value={form.warm_days}
          onChange={(e) => updateField('warm_days', Number(e.target.value))}
          data-testid="retention-policy-warm-days"
          aria-invalid={Boolean(errors.warm_days)}
        />
        {errors.warm_days && (
          <div className="retention-policy__field-error" data-testid="retention-policy-warm-days-error">
            {errors.warm_days}
          </div>
        )}
      </div>

      <div className="retention-policy__field">
        <label htmlFor="cold_action" className="retention-policy__field-label">
          Cold tier action
        </label>
        <select
          id="cold_action"
          name="cold_action"
          className="retention-policy__select"
          value={form.cold_action}
          onChange={(e) => updateField('cold_action', e.target.value as ColdActionDto)}
          data-testid="retention-policy-cold-action"
        >
          <option value="drop">Drop</option>
          <option value="archive">Archive to S3</option>
        </select>
      </div>

      {form.cold_action === 'archive' && (
        <div className="retention-policy__field" data-testid="retention-policy-archive-field">
          <label htmlFor="archive_url" className="retention-policy__field-label">
            Archive URL
          </label>
          <p className="retention-policy__field-help">Must start with s3:// or gs://</p>
          <input
            id="archive_url"
            name="archive_url"
            type="text"
            className={`retention-policy__input${errors.archive_url ? ' retention-policy__input--error' : ''}`}
            value={form.archive_url ?? ''}
            onChange={(e) => updateField('archive_url', e.target.value)}
            placeholder="s3://my-bucket/aasm-archive/"
            data-testid="retention-policy-archive-url"
            aria-invalid={Boolean(errors.archive_url)}
          />
          {errors.archive_url && (
            <div className="retention-policy__field-error" data-testid="retention-policy-archive-url-error">
              {errors.archive_url}
            </div>
          )}
        </div>
      )}

      <div className="retention-policy__actions">
        <button
          type="button"
          className="retention-policy__button retention-policy__button--primary"
          onClick={handleSave}
          disabled={hasErrors || saving || running}
          data-testid="retention-policy-save"
        >
          {saving ? 'Saving…' : 'Save Changes'}
        </button>
        <button
          type="button"
          className="retention-policy__button"
          onClick={() => handleRun(true)}
          disabled={saving || running}
          data-testid="retention-policy-dry-run"
        >
          {running ? 'Running…' : 'Run Now (Dry Run)'}
        </button>
        <button
          type="button"
          className="retention-policy__button"
          onClick={() => handleRun(false)}
          disabled={saving || running}
          data-testid="retention-policy-run"
        >
          {running ? 'Running…' : 'Run Now'}
        </button>
      </div>

      {statusMsg && (
        <div
          className={`retention-policy__status retention-policy__status--${statusMsg.kind}`}
          data-testid="retention-policy-status"
          role={statusMsg.kind === 'error' ? 'alert' : 'status'}
        >
          {statusMsg.text}
        </div>
      )}

      <div className="retention-policy__last-run" data-testid="retention-policy-last-run">
        <h2>Last retention run</h2>
        {lastRun ? (
          <>
            <p>
              Ran at: <strong>{new Date(lastRun.ran_at).toUTCString()}</strong>
              {lastRun.dry_run && (
                <span data-testid="retention-policy-last-run-dry-run-tag"> (dry run)</span>
              )}
            </p>
            <div className="retention-policy__stat-grid">
              <div>
                <div className="retention-policy__stat-label">Hot rows</div>
                <div className="retention-policy__stat-value" data-testid="retention-policy-stat-hot">
                  {lastRun.hot_rows.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="retention-policy__stat-label">Compressed</div>
                <div className="retention-policy__stat-value" data-testid="retention-policy-stat-compressed">
                  {lastRun.compressed_rows.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="retention-policy__stat-label">Archived</div>
                <div className="retention-policy__stat-value" data-testid="retention-policy-stat-archived">
                  {lastRun.archived_rows.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="retention-policy__stat-label">Dropped</div>
                <div className="retention-policy__stat-value" data-testid="retention-policy-stat-dropped">
                  {lastRun.dropped_rows.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="retention-policy__stat-label">Freed</div>
                <div className="retention-policy__stat-value" data-testid="retention-policy-stat-freed">
                  {formatBytes(lastRun.freed_bytes)}
                </div>
              </div>
            </div>
          </>
        ) : (
          <p className="retention-policy__last-run-empty" data-testid="retention-policy-last-run-empty">
            No retention run has completed yet.
          </p>
        )}
      </div>
    </section>
  )
}
