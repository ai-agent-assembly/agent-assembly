import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

import {
  MEASUREMENT_ID,
  analyticsBootstrap,
  hardenHtml,
  hardenSite,
  scriptBlocks,
} from './harden_published_analytics.mjs';

const docsRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const privateCanary = 'PRIVATE_PROMPT_PRIVATE_REPO';
const workflow = fs.readFileSync(
  path.resolve(docsRoot, '../.github/workflows/docs.yml'),
  'utf8',
);

assert.match(
  workflow,
  /node docs\/scripts\/harden_published_analytics\.mjs docs\/book \\\n\s+--public-prefix \/core\/latest\//,
);
const assembleStart = workflow.indexOf('cp docs/site-root-index.html _site/index.html');
const lastMile = workflow.indexOf('node docs/scripts/harden_published_analytics.mjs _site');
const upload = workflow.indexOf('- name: Upload Pages artifact');
assert.ok(assembleStart >= 0 && assembleStart < lastMile, 'hardening follows site assembly');
assert.ok(lastMile < upload, 'hardening precedes Pages artifact upload');

function analyticsScript(html) {
  const matches = scriptBlocks(html).filter((block) => block.body.includes(MEASUREMENT_ID));
  assert.equal(matches.length, 1, 'one analytics bootstrap must be present');
  return matches[0].body;
}

function execute(script, storedConsent = null) {
  const calls = [];
  const context = {
    dataLayer: calls,
    window: null,
    localStorage: { getItem: () => storedConsent },
    location: {
      href: `https://docs.agent-assembly.com/core/404.html?prompt=${privateCanary}`,
      pathname: `/${privateCanary}`,
    },
    document: { referrer: privateCanary, title: privateCanary },
    Date,
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(script, context);
  return { calls, context };
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertSafePageView(calls, expectedLocation) {
  const setIndex = calls.findIndex((call) => call[0] === 'set');
  const configIndex = calls.findIndex((call) => call[0] === 'config');
  const pageViewIndex = calls.findIndex(
    (call) => call[0] === 'event' && call[1] === 'page_view',
  );
  assert.ok(setIndex >= 0 && setIndex < configIndex, 'global context precedes config');
  assert.ok(configIndex < pageViewIndex, 'manual pageview follows disabled automatic pageview');

  const expectedContext = {
    page_location: expectedLocation,
    page_referrer: '',
    page_title: 'Agent Assembly documentation',
  };
  assert.deepEqual(plain(calls[setIndex][1]), expectedContext);
  assert.deepEqual(plain(calls[configIndex][2]), {
    anonymize_ip: true,
    send_page_view: false,
    ...expectedContext,
  });
  assert.deepEqual(plain(calls[pageViewIndex][2]), {
    page_path: new URL(expectedLocation).pathname,
    ...expectedContext,
    send_to: MEASUREMENT_ID,
  });
  assert.equal(JSON.stringify(calls).includes(privateCanary), false);
}

for (const source of ['theme/head.hbs', 'site-root-index.html']) {
  const html = fs.readFileSync(path.join(docsRoot, source), 'utf8');
  const script = analyticsScript(html);
  assert.equal(
    script,
    analyticsBootstrap('https://docs.agent-assembly.com/core/'),
    `${source} must use the canonical generated bootstrap`,
  );
  const { calls } = execute(script);
  assertSafePageView(calls, 'https://docs.agent-assembly.com/core/');
  if (source === 'theme/head.hbs') {
    assert.ok(html.includes("var title = 'Docs feedback: /core/';"));
    assert.ok(
      html.includes(
        "var body = 'Page: https://docs.agent-assembly.com/core/\\n\\n"
          + "What could be improved?\\n';",
      ),
    );
    assert.equal(html.includes('location.href'), false);
    assert.equal(html.includes('location.pathname'), false);
  }
}

const historicalBootstrap = `
  window.dataLayer = window.dataLayer || [];
  function gtag() { dataLayer.push(arguments); }
  gtag('consent', 'default', { 'analytics_storage': 'denied' });
  gtag('config', '${MEASUREMENT_ID}', { 'anonymize_ip': true });
`;
const historicalHtml = `<!doctype html><html><head>
  <ScRiPt data-old="yes">${historicalBootstrap}</sCrIpT   >
  <script async src="https://www.googletagmanager.com/gtag/js?id=${MEASUREMENT_ID}"></script>
</head><body><script>
  function sendFeedback(value) {
    gtag('event', 'feedback', { 'value': value, 'page_path': location.pathname });
  }
  function issueUrl() {
    var title = 'Docs feedback: ' + location.pathname;
    var body = 'Page: ' + location.href + '\\n\\nWhat could be improved?\\n';
    return title + body;
  }
</script></body></html>`;
const canonical = 'https://docs.agent-assembly.com/core/v0.0.1-rc.7/guide.html';
const hardened = hardenHtml(historicalHtml, canonical);
assert.equal(hardened.includes("'page_path': location.pathname"), false);
assert.equal(hardened.includes("'Docs feedback: ' + location.pathname"), false);
assert.equal(hardened.includes("'Page: ' + location.href"), false);
assert.ok(hardened.includes('var title = "Docs feedback: /core/v0.0.1-rc.7/guide.html";'));
assert.ok(hardened.includes(`var body = "Page: ${canonical}\\n\\nWhat could be improved?\\n";`));
const granted = execute(analyticsScript(hardened), 'granted');
assertSafePageView(granted.calls, canonical);
assert.ok(
  granted.calls.some(
    (call) => call[0] === 'consent' && call[1] === 'update'
      && call[2].analytics_storage === 'granted',
  ),
  'stored consent remains effective',
);

granted.context.gtag('event', 'feedback', {
  value: 1,
  page_path: `/${privateCanary}`,
  repo: privateCanary,
});
assert.deepEqual(plain(granted.calls.at(-1)), ['event', 'feedback', {
  value: 1,
  page_id: 'docs',
  page_location: canonical,
  page_referrer: '',
  page_title: 'Agent Assembly documentation',
}]);
assert.equal(JSON.stringify(granted.calls).includes(privateCanary), false);

assert.throws(
  () => analyticsBootstrap(`https://docs.agent-assembly.com/core/?prompt=${privateCanary}`),
  /invalid canonical documentation URL/,
);
assert.throws(
  () => analyticsBootstrap('https://private@docs.agent-assembly.com/core/'),
  /invalid canonical documentation URL/,
);
assert.throws(
  () => hardenHtml('<html><script>no analytics</script></html>', canonical),
  /expected one analytics bootstrap, found 0/,
);
assert.throws(
  () => hardenHtml(
    historicalHtml.replace("var title = 'Docs feedback: ' + location.pathname;", 'var heading = location.pathname;'),
    canonical,
  ),
  /expected one feedback title, found 0/,
);
assert.throws(
  () => hardenHtml(
    historicalHtml.replace('return title + body;', 'var detail = document.referrer; return title + body + detail;'),
    canonical,
  ),
  /feedback link still contains runtime page identity/,
);

const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-docs-privacy-'));
try {
  fs.mkdirSync(path.join(fixtureRoot, 'v0.0.1-rc.7'), { recursive: true });
  fs.mkdirSync(path.join(fixtureRoot, 'v0.0.1-alpha.1'), { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot, 'index.html'), historicalHtml);
  fs.writeFileSync(path.join(fixtureRoot, 'v0.0.1-rc.7', 'index.html'), historicalHtml);
  fs.writeFileSync(
    path.join(fixtureRoot, 'v0.0.1-alpha.1', 'index.html'),
    '<!doctype html><title>Pre-analytics archived documentation</title>',
  );
  assert.equal(hardenSite(fixtureRoot), 2);
  assertSafePageView(
    execute(analyticsScript(fs.readFileSync(path.join(fixtureRoot, 'index.html'), 'utf8'))).calls,
    'https://docs.agent-assembly.com/core/',
  );
  const archived = fs.readFileSync(
    path.join(fixtureRoot, 'v0.0.1-rc.7', 'index.html'),
    'utf8',
  );
  assertSafePageView(
    execute(analyticsScript(archived)).calls,
    'https://docs.agent-assembly.com/core/v0.0.1-rc.7/',
  );

  const beforeInvalidPrefix = fs.readFileSync(path.join(fixtureRoot, 'index.html'), 'utf8');
  assert.throws(() => hardenSite(fixtureRoot, '/core/../private/'), /public prefix/);
  assert.equal(
    fs.readFileSync(path.join(fixtureRoot, 'index.html'), 'utf8'),
    beforeInvalidPrefix,
    'an invalid prefix must not rewrite the artifact',
  );

  fs.writeFileSync(
    path.join(fixtureRoot, 'v0.0.1-rc.7', 'broken.html'),
    historicalHtml.replace('</head>', `<script>${historicalBootstrap}</script></head>`),
  );
  const beforePartialFailure = fs.readFileSync(path.join(fixtureRoot, 'index.html'), 'utf8');
  assert.throws(() => hardenSite(fixtureRoot), /expected one analytics bootstrap, found 2/);
  assert.equal(
    fs.readFileSync(path.join(fixtureRoot, 'index.html'), 'utf8'),
    beforePartialFailure,
    'preflight must finish before any rendered page is rewritten',
  );
  fs.rmSync(path.join(fixtureRoot, 'v0.0.1-rc.7', 'broken.html'));

  fs.symlinkSync('/tmp', path.join(fixtureRoot, 'escaped'));
  assert.throws(() => hardenSite(fixtureRoot), /refusing rendered symlink/);
} finally {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
}

console.log('core analytics privacy VM checks passed');
