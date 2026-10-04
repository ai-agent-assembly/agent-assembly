import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const DOCS_ORIGIN = 'https://docs.agent-assembly.com';
export const MEASUREMENT_ID = 'G-EV2FPGTJJB';
const FIXED_TITLE = 'Agent Assembly documentation';

function scanTagEnd(html, start) {
  let quote = null;
  for (let index = start; index < html.length; index += 1) {
    const char = html[index];
    if (quote !== null) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === '>') {
      return index + 1;
    }
  }
  throw new Error('unterminated HTML tag');
}

function isTagBoundary(char) {
  return char === undefined || char === '>' || char === '/' || /\s/.test(char);
}

export function scriptBlocks(html) {
  const blocks = [];
  const lower = html.toLowerCase();
  let cursor = 0;
  while (cursor < html.length) {
    const start = lower.indexOf('<script', cursor);
    if (start === -1) break;
    if (!isTagBoundary(lower[start + 7])) {
      cursor = start + 7;
      continue;
    }

    const bodyStart = scanTagEnd(html, start + 7);
    let closeStart = lower.indexOf('</script', bodyStart);
    while (closeStart !== -1 && !isTagBoundary(lower[closeStart + 8])) {
      closeStart = lower.indexOf('</script', closeStart + 8);
    }
    if (closeStart === -1) throw new Error('script element has no closing tag');
    const end = scanTagEnd(html, closeStart + 8);
    blocks.push({
      start,
      bodyStart,
      closeStart,
      end,
      openTag: html.slice(start, bodyStart),
      body: html.slice(bodyStart, closeStart),
    });
    cursor = end;
  }
  return blocks;
}

function jsString(value) {
  return JSON.stringify(value).replaceAll('<', '\\u003c');
}

export function analyticsBootstrap(pageLocation) {
  const canonical = new URL(pageLocation);
  if (
    canonical.origin !== DOCS_ORIGIN
    || canonical.username
    || canonical.password
    || canonical.search
    || canonical.hash
  ) {
    throw new Error(`invalid canonical documentation URL: ${pageLocation}`);
  }
  const locationLiteral = jsString(canonical.href);
  const pathLiteral = jsString(canonical.pathname);

  return `
  // Privacy boundary: only build-generated public documentation identity may
  // reach analytics. Runtime URL, referrer, title, and arbitrary event fields
  // are deliberately outside this boundary.
  window.dataLayer = window.dataLayer || [];
  function gtag() {
    if (arguments[0] === 'event' && arguments[1] === 'feedback') {
      var vote = arguments[2] && arguments[2].value === 1 ? 1 : 0;
      dataLayer.push(['event', 'feedback', {
        'value': vote,
        'page_id': 'docs',
        'page_location': ${locationLiteral},
        'page_referrer': '',
        'page_title': ${jsString(FIXED_TITLE)}
      }]);
      return;
    }
    dataLayer.push(arguments);
  }
  // Consent Mode v2 — deny analytics/ads storage until the visitor opts in.
  gtag('consent', 'default', {
    'analytics_storage': 'denied',
    'ad_storage': 'denied',
    'ad_user_data': 'denied',
    'ad_personalization': 'denied'
  });
  // Re-apply a stored opt-in before the first hit fires.
  try {
    if (window.localStorage && localStorage.getItem('aa-analytics-consent') === 'granted') {
      gtag('consent', 'update', { 'analytics_storage': 'granted' });
    }
  } catch (e) {}
  gtag('js', new Date());
  gtag('set', {
    'page_location': ${locationLiteral},
    'page_referrer': '',
    'page_title': ${jsString(FIXED_TITLE)}
  });
  gtag('config', '${MEASUREMENT_ID}', {
    'anonymize_ip': true,
    'send_page_view': false,
    'page_location': ${locationLiteral},
    'page_referrer': '',
    'page_title': ${jsString(FIXED_TITLE)}
  });
  gtag('event', 'page_view', {
    'page_path': ${pathLiteral},
    'page_location': ${locationLiteral},
    'page_referrer': '',
    'page_title': ${jsString(FIXED_TITLE)},
    'send_to': '${MEASUREMENT_ID}'
  });
`;
}

function isAnalyticsBootstrap(block) {
  return block.body.includes(MEASUREMENT_ID)
    && block.body.includes("gtag('config'")
    && block.body.includes("gtag('consent', 'default'");
}

function replaceUnique(body, pattern, replacement, label) {
  const matches = [...body.matchAll(pattern)];
  if (matches.length !== 1) {
    throw new Error(`expected one feedback ${label}, found ${matches.length}`);
  }
  return body.replace(pattern, replacement);
}

function hardenFeedback(html, pageLocation) {
  const canonical = new URL(pageLocation);
  const blocks = scriptBlocks(html);
  let output = html;
  for (const block of blocks.reverse()) {
    if (!block.body.includes('function issueUrl()')) continue;
    let body = block.body;
    if (body.includes("'page_path': location.pathname")) {
      body = replaceUnique(
        body,
        /gtag\('event', 'feedback', \{ 'value': value, 'page_path': location\.pathname \}\);/g,
        "gtag('event', 'feedback', { 'value': value, 'page_id': 'docs' });",
        'event payload',
      );
    }
    body = replaceUnique(
      body,
      /var title = [^\r\n]+;/g,
      `var title = ${jsString(`Docs feedback: ${canonical.pathname}`)};`,
      'title',
    );
    body = replaceUnique(
      body,
      /var body = [^\r\n]+;/g,
      `var body = ${jsString(`Page: ${canonical.href}\n\nWhat could be improved?\n`)};`,
      'body',
    );
    if (body.includes('location.href') || body.includes('location.pathname')) {
      throw new Error('feedback link still contains runtime page identity');
    }
    output = output.slice(0, block.bodyStart) + body + output.slice(block.closeStart);
  }
  return output;
}

function publicUrl(relativeFile, publicPrefix) {
  const parts = relativeFile.split(path.sep);
  if (parts.some((part) => part === '' || part === '.' || part === '..')) {
    throw new Error(`unsafe rendered path: ${relativeFile}`);
  }
  const encoded = parts.map((part) => encodeURIComponent(part)).join('/');
  let pagePath = `${publicPrefix}${encoded}`;
  if (relativeFile === 'index.html') pagePath = publicPrefix;
  else if (pagePath.endsWith('/index.html')) pagePath = pagePath.slice(0, -10);
  return new URL(pagePath, `${DOCS_ORIGIN}/`).href;
}

export function hardenHtml(html, pageLocation) {
  const blocks = scriptBlocks(html);
  const targets = blocks.filter(isAnalyticsBootstrap);
  if (targets.length !== 1) {
    throw new Error(`expected one analytics bootstrap, found ${targets.length}`);
  }
  const target = targets[0];
  const withBootstrap = html.slice(0, target.bodyStart)
    + analyticsBootstrap(pageLocation)
    + html.slice(target.closeStart);
  return hardenFeedback(withBootstrap, pageLocation);
}

function renderedFiles(root) {
  const files = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const item = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`refusing rendered symlink: ${item}`);
      if (entry.isDirectory()) visit(item);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.html')) files.push(item);
    }
  }
  visit(root);
  return files.sort();
}

export function hardenSite(siteRoot, publicPrefix = '/core/') {
  if (
    !/^\/(?:[A-Za-z0-9._~-]+\/)*$/.test(publicPrefix)
    || publicPrefix.split('/').some((part) => part === '.' || part === '..')
  ) {
    throw new Error('public prefix must be a safe absolute path ending with /');
  }
  const root = fs.realpathSync(siteRoot);
  const files = renderedFiles(root);
  if (files.length === 0) throw new Error(`no rendered HTML under ${root}`);

  const updates = [];
  for (const file of files) {
    const relative = path.relative(root, file);
    const html = fs.readFileSync(file, 'utf8');
    // Early archived releases predate analytics. They have nothing to repair
    // and must remain faithful snapshots. A page that references this site's
    // measurement ID is in scope and must carry exactly one valid boundary.
    if (!html.includes(MEASUREMENT_ID)) continue;
    updates.push([file, hardenHtml(html, publicUrl(relative, publicPrefix))]);
  }
  for (const [file, html] of updates) fs.writeFileSync(file, html);
  return updates.length;
}

function parseArguments(argv) {
  const positional = [];
  let publicPrefix = '/core/';
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--public-prefix') {
      publicPrefix = argv[index + 1];
      index += 1;
    } else {
      positional.push(argv[index]);
    }
  }
  if (positional.length !== 1 || publicPrefix === undefined) {
    throw new Error('usage: harden_published_analytics.mjs SITE_ROOT [--public-prefix /core/]');
  }
  return { siteRoot: positional[0], publicPrefix };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const { siteRoot, publicPrefix } = parseArguments(process.argv.slice(2));
  const count = hardenSite(siteRoot, publicPrefix);
  console.log(`Hardened analytics identity in ${count} rendered HTML file(s).`);
}
