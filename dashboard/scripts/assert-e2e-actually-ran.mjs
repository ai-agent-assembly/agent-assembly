#!/usr/bin/env node
/**
 * Fail unless the real-backend specs actually RAN (AAASM-5694, AC2).
 *
 * # The defect this exists to close
 *
 * `verify-aaasm-5360.spec.ts` skips when nothing is listening on the API port,
 * which is correct for a spec that also runs on a laptop — a spec that *fails*
 * without its fixture gets quarantined and then ignored. But Playwright then
 * exits **0** with "4 skipped", so a CI lane that checks only the exit code
 * records real-backend verification as having happened while running nothing.
 *
 * That is the same shape as the bug the whole lane addresses: a signal that
 * reads as evidence while measuring nothing. An exit code cannot tell "passed"
 * from "skipped everything", so this reads the JSON report and asserts the
 * population, not the verdict.
 *
 * Usage: node scripts/assert-e2e-actually-ran.mjs <report.json> <min-tests>
 */

import { readFileSync } from 'node:fs'

const [, , reportPath, minTestsRaw] = process.argv
const minTests = Number.parseInt(minTestsRaw ?? '1', 10)

if (!reportPath) {
  console.error('usage: assert-e2e-actually-ran.mjs <report.json> <min-tests>')
  process.exit(2)
}

let report
try {
  report = JSON.parse(readFileSync(reportPath, 'utf8'))
} catch (error) {
  // A missing report means Playwright did not get far enough to write one.
  // That is a lane failure, and it must not be reported as "nothing to check".
  console.error(`assert-e2e-actually-ran: cannot read ${reportPath}: ${error.message}`)
  process.exit(2)
}

const outcomes = { expected: 0, unexpected: 0, skipped: 0, flaky: 0 }
const skippedTitles = []

function walk(suite) {
  for (const spec of suite.specs ?? []) {
    for (const testCase of spec.tests ?? []) {
      const status = testCase.status ?? 'unknown'
      if (status in outcomes) {
        outcomes[status] += 1
      }
      if (status === 'skipped') {
        skippedTitles.push(spec.title)
      }
    }
  }
  for (const child of suite.suites ?? []) {
    walk(child)
  }
}

for (const suite of report.suites ?? []) {
  walk(suite)
}

const ran = outcomes.expected + outcomes.unexpected + outcomes.flaky
const total = ran + outcomes.skipped

// Always print the denominator. A count without its population is not a
// measurement, and a test selection that silently shrank must be visible here
// rather than inferred from a green tick.
console.log(
  `assert-e2e-actually-ran: ${total} test(s) collected — ` +
    `${outcomes.expected} expected, ${outcomes.unexpected} unexpected, ` +
    `${outcomes.flaky} flaky, ${outcomes.skipped} skipped (minimum required: ${minTests})`
)

let failed = false

if (outcomes.skipped > 0) {
  console.error(
    `assert-e2e-actually-ran: FAIL — ${outcomes.skipped} real-backend test(s) skipped:`
  )
  for (const title of skippedTitles) {
    console.error(`  - ${title}`)
  }
  console.error(
    '  A skipped real-backend suite must not be recordable as a pass. The usual\n' +
      '  cause is that the aa-api-server did not come up; check the boot step.'
  )
  failed = true
}

if (ran < minTests) {
  console.error(
    `assert-e2e-actually-ran: FAIL — only ${ran} test(s) ran, expected at least ${minTests}. ` +
      'A shrinking selection is how this lane would quietly stop testing anything.'
  )
  failed = true
}

process.exit(failed ? 1 : 0)
