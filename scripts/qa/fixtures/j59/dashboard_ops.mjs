// J59 step 6 (AAASM-4979): operate the real dashboard served by the candidate gateway.
//
// Driven by scripts/qa/j59_live_agent.py (`check_dashboard_operations`), which copies this file
// next to a `node_modules` that holds @playwright/test, runs it against a loopback URL and reads the
// single `RESULT <json>` line. Exit code is 0 only when every step passed. The harness does not trust
// this file's verdict for the approval actions: it re-reads the approval store through the API.
//
// Input (argv[2]) is a JSON file:
//   { url, apiKey, agents: [name...],
//     auditRows: [{ digest, label, decision, summary? }],   // what the audit API holds for the harness agent
//     approveAgent: name,                                   // two pending requests: approve one, reject the other
//   }
// Every assertion is on rendered content (names, labels, decisions, toasts), never on page load alone.
import { chromium } from '@playwright/test'
import { readFileSync } from 'node:fs'

const spec = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const steps = []
const apiFailures = []
const consoleErrors = []

async function step(name, fn) {
  try {
    const detail = await fn()
    steps.push({ name, ok: true, detail: detail ?? '' })
  } catch (e) {
    steps.push({ name, ok: false, detail: String(e?.message ?? e).split('\n')[0].slice(0, 400) })
  }
}

function must(cond, msg) {
  if (!cond) throw new Error(msg)
}

const browser = await chromium.launch()
const page = await browser.newPage()
page.on('response', (r) => {
  if (r.url().includes('/api/') && r.status() >= 400) apiFailures.push(`${r.status()} ${new URL(r.url()).pathname}`)
})
page.on('console', (m) => {
  if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200))
})
page.on('pageerror', (e) => consoleErrors.push(String(e).slice(0, 200)))

try {
  await step('login-with-api-key', async () => {
    await page.goto(spec.url + '/')
    await page.getByLabel('API key').waitFor({ timeout: 30000 })
    must(/sign in with an API key/i.test(await page.locator('body').innerText()), 'login page does not offer API key sign-in')
    await page.getByLabel('API key').fill(spec.apiKey)
    await page.getByRole('button', { name: 'Sign in with API key' }).click()
    await page.waitForURL(/\/overview/, { timeout: 30000 })
    await page.getByText('runtime ok').first().waitFor({ timeout: 30000 })
    return 'signed in; shell shows "runtime ok"'
  })

  await step('agent-list-shows-harness-agents', async () => {
    await page.goto(spec.url + '/agents')
    for (const name of spec.agents) {
      const row = page.getByRole('row').filter({ hasText: name })
      await row.first().waitFor({ timeout: 30000 })
      const text = await row.first().innerText()
      must(/PYTHON/i.test(text) && /ENFORCE/i.test(text) && /Active/i.test(text), `row for ${name} is not an active enforced python agent: ${text.replace(/\s+/g, ' ')}`)
    }
    return `agent rows present and active: ${spec.agents.join(', ')}`
  })

  await step('audit-log-shows-allow-deny-approval', async () => {
    await page.goto(spec.url + '/audit')
    await page.getByText(/entries matching the current filter are loaded/i).waitFor({ timeout: 30000 })
    for (const want of spec.auditRows) {
      const row = page
        .getByRole('row')
        .filter({ hasText: want.digest })
        .filter({ hasText: want.label })
        .filter({ hasText: want.decision })
        .filter({ hasText: want.summary ?? '' })
      must((await row.count()) >= 1, `no audit row for agent ${want.digest}… with ${want.label} / ${want.decision}${want.summary ? ' / ' + want.summary : ''}`)
    }
    return `${spec.auditRows.length} expected audit rows are rendered with their event label and decision`
  })

  await step('approvals-page-lists-pending-and-resolves-from-ui', async () => {
    await page.goto(spec.url + '/approvals')
    const rows = () => page.getByRole('row').filter({ hasText: spec.approveAgent })
    await rows().first().waitFor({ timeout: 30000 })
    const n = await rows().count()
    must(n >= 2, `expected at least 2 pending requests for ${spec.approveAgent}, found ${n}`)
    must(/Approve/.test(await rows().first().innerText()) && /Reject/.test(await rows().first().innerText()), 'pending row has no Approve/Reject actions')
    await rows().first().getByRole('button', { name: 'Approve' }).click()
    await page.getByText(/Approved 1 request/i).waitFor({ timeout: 30000 })
    await page.waitForFunction((a) => [...document.querySelectorAll('tr')].filter((r) => r.innerText.includes(a)).length === n - 1, spec.approveAgent, { timeout: 30000 }).catch(() => {})
    await rows().first().getByRole('button', { name: 'Reject' }).click()
    await page.getByText(/Rejected 1 request/i).waitFor({ timeout: 30000 })
    return 'approved one pending request and rejected another through the UI (toasts shown)'
  })

  await step('no-failed-api-calls', async () => {
    must(apiFailures.length === 0, `API calls failed while operating the dashboard: ${apiFailures.slice(0, 5).join(', ')}`)
    return 'every /api request returned < 400'
  })
} finally {
  await browser.close()
}

const ok = steps.every((s) => s.ok)
console.log('RESULT ' + JSON.stringify({ ok, steps, consoleErrors: consoleErrors.slice(0, 10), apiFailures: apiFailures.slice(0, 10) }))
process.exit(ok ? 0 : 1)
