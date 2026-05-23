import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { RetentionPolicyPage } from './RetentionPolicy'
import type {
  RetentionPolicyClient,
  RetentionPolicyDocument,
  RetentionRunStatsDto,
  UpdateRetentionPolicyRequest,
} from '../../api/retention'

function makeDoc(overrides: Partial<RetentionPolicyDocument> = {}): RetentionPolicyDocument {
  return {
    hot_days: 30,
    warm_days: 90,
    cold_action: 'drop',
    archive_url: null,
    dry_run: false,
    schedule: '0 0 3 * * *',
    last_run: null,
    ...overrides,
  }
}

function makeStats(overrides: Partial<RetentionRunStatsDto> = {}): RetentionRunStatsDto {
  return {
    ran_at: '2026-05-20T03:00:12Z',
    hot_rows: 1234,
    compressed_rows: 1452,
    archived_rows: 0,
    dropped_rows: 388,
    freed_bytes: 127 * 1024 * 1024,
    dry_run: false,
    ...overrides,
  }
}

interface FakeClientOptions {
  initialDoc?: RetentionPolicyDocument
  updateError?: string
  runError?: string
  runResult?: RetentionRunStatsDto
}

interface FakeClient extends RetentionPolicyClient {
  calls: {
    get: number
    update: UpdateRetentionPolicyRequest[]
    run: boolean[]
  }
}

function makeFakeClient(options: FakeClientOptions = {}): FakeClient {
  const initialDoc = options.initialDoc ?? makeDoc()
  let currentDoc = initialDoc
  const calls = { get: 0, update: [] as UpdateRetentionPolicyRequest[], run: [] as boolean[] }
  return {
    calls,
    async get() {
      calls.get += 1
      return structuredClone(currentDoc)
    },
    async update(req) {
      calls.update.push(req)
      if (options.updateError) throw new Error(options.updateError)
      currentDoc = {
        ...currentDoc,
        hot_days: req.hot_days,
        warm_days: req.warm_days,
        cold_action: req.cold_action,
        archive_url: req.archive_url ?? null,
      }
      return structuredClone(currentDoc)
    },
    async run(dryRun) {
      calls.run.push(dryRun)
      if (options.runError) throw new Error(options.runError)
      const stats = options.runResult ?? makeStats({ dry_run: dryRun })
      currentDoc = { ...currentDoc, last_run: stats }
      return structuredClone(stats)
    },
  }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('RetentionPolicyPage', () => {
  it('renders the loading state then the current config', async () => {
    const client = makeFakeClient({ initialDoc: makeDoc({ hot_days: 15, warm_days: 60 }) })
    render(<RetentionPolicyPage client={client} />)

    expect(screen.getByTestId('retention-policy-loading')).toBeInTheDocument()

    const hotInput = await screen.findByTestId<HTMLInputElement>('retention-policy-hot-days')
    expect(hotInput.value).toBe('15')
    const warmInput = screen.getByTestId<HTMLInputElement>('retention-policy-warm-days')
    expect(warmInput.value).toBe('60')
    expect(client.calls.get).toBe(1)
  })

  it('shows the empty-state when there is no last run', async () => {
    const client = makeFakeClient()
    render(<RetentionPolicyPage client={client} />)

    expect(await screen.findByTestId('retention-policy-last-run-empty')).toBeInTheDocument()
  })

  it('shows last-run stats when the GET response carries them', async () => {
    const client = makeFakeClient({
      initialDoc: makeDoc({ last_run: makeStats({ hot_rows: 5_000, dropped_rows: 200 }) }),
    })
    render(<RetentionPolicyPage client={client} />)

    expect(await screen.findByTestId('retention-policy-stat-hot')).toHaveTextContent('5,000')
    expect(screen.getByTestId('retention-policy-stat-dropped')).toHaveTextContent('200')
    expect(screen.queryByTestId('retention-policy-last-run-empty')).toBeNull()
  })

  it('disables Save and shows the warm_days <= hot_days error when invalid', async () => {
    const user = userEvent.setup()
    const client = makeFakeClient()
    render(<RetentionPolicyPage client={client} />)

    const warmInput = await screen.findByTestId<HTMLInputElement>('retention-policy-warm-days')
    await user.clear(warmInput)
    await user.type(warmInput, '30')

    expect(screen.getByTestId('retention-policy-warm-days-error')).toBeInTheDocument()
    expect(screen.getByTestId<HTMLButtonElement>('retention-policy-save')).toBeDisabled()
  })

  it('shows the archive_url required error when cold_action switches to archive', async () => {
    const user = userEvent.setup()
    const client = makeFakeClient()
    render(<RetentionPolicyPage client={client} />)

    const select = await screen.findByTestId<HTMLSelectElement>('retention-policy-cold-action')
    await user.selectOptions(select, 'archive')

    expect(screen.getByTestId('retention-policy-archive-field')).toBeInTheDocument()
    expect(screen.getByTestId('retention-policy-archive-url-error')).toHaveTextContent(
      /required when cold_action is "archive"/,
    )
    expect(screen.getByTestId<HTMLButtonElement>('retention-policy-save')).toBeDisabled()
  })

  it('rejects archive_url values that lack a s3:// or gs:// prefix', async () => {
    const user = userEvent.setup()
    const client = makeFakeClient()
    render(<RetentionPolicyPage client={client} />)

    const select = await screen.findByTestId<HTMLSelectElement>('retention-policy-cold-action')
    await user.selectOptions(select, 'archive')

    const urlInput = await screen.findByTestId<HTMLInputElement>('retention-policy-archive-url')
    await user.type(urlInput, 'https://example.com/bucket')

    expect(screen.getByTestId('retention-policy-archive-url-error')).toHaveTextContent(/s3:\/\/ or gs:\/\//)
    expect(screen.getByTestId<HTMLButtonElement>('retention-policy-save')).toBeDisabled()
  })

  it('Save Changes fires PUT with the edited values and renders a success status', async () => {
    const user = userEvent.setup()
    const client = makeFakeClient()
    render(<RetentionPolicyPage client={client} />)

    const hotInput = await screen.findByTestId<HTMLInputElement>('retention-policy-hot-days')
    await user.clear(hotInput)
    await user.type(hotInput, '15')

    const saveBtn = screen.getByTestId<HTMLButtonElement>('retention-policy-save')
    expect(saveBtn).not.toBeDisabled()
    await user.click(saveBtn)

    await waitFor(() => {
      expect(client.calls.update.length).toBe(1)
    })
    expect(client.calls.update[0]?.hot_days).toBe(15)
    expect(client.calls.update[0]?.warm_days).toBe(90)
    expect(client.calls.update[0]?.cold_action).toBe('drop')

    await waitFor(() => {
      expect(screen.getByTestId('retention-policy-status').textContent).toMatch(/updated/i)
    })
  })

  it('renders an error status when Save fails', async () => {
    const user = userEvent.setup()
    const client = makeFakeClient({ updateError: 'gateway rejected' })
    render(<RetentionPolicyPage client={client} />)

    const saveBtn = await screen.findByTestId<HTMLButtonElement>('retention-policy-save')
    await user.click(saveBtn)

    await waitFor(() => {
      expect(screen.getByTestId('retention-policy-status').textContent).toMatch(/Save failed/i)
    })
  })

  it('Run Now (Dry Run) calls run(true) and renders the returned stats', async () => {
    const user = userEvent.setup()
    const client = makeFakeClient({ runResult: makeStats({ hot_rows: 9_999, dry_run: true }) })
    render(<RetentionPolicyPage client={client} />)

    const dryRunBtn = await screen.findByTestId<HTMLButtonElement>('retention-policy-dry-run')
    await user.click(dryRunBtn)

    await waitFor(() => {
      expect(client.calls.run).toEqual([true])
    })
    expect(await screen.findByTestId('retention-policy-stat-hot')).toHaveTextContent('9,999')
    expect(screen.getByTestId('retention-policy-last-run-dry-run-tag')).toBeInTheDocument()
  })

  it('Run Now (non-dry) calls run(false)', async () => {
    const user = userEvent.setup()
    const client = makeFakeClient()
    render(<RetentionPolicyPage client={client} />)

    const runBtn = await screen.findByTestId<HTMLButtonElement>('retention-policy-run')
    await user.click(runBtn)

    await waitFor(() => {
      expect(client.calls.run).toEqual([false])
    })
  })

  it('shows a load error when GET fails', async () => {
    const client: RetentionPolicyClient = {
      async get() {
        throw new Error('boom')
      },
      async update() {
        throw new Error('unreachable')
      },
      async run() {
        throw new Error('unreachable')
      },
    }
    render(<RetentionPolicyPage client={client} />)

    expect(await screen.findByTestId('retention-policy-load-error')).toHaveTextContent(/boom/)
  })
})
