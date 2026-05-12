/* global React */
// Tweaks panel for Agent Assembly hi-fi.
// Knobs cluster into three sections:
//   1. Demo / Story  — posture preset, live ops behaviour, approvals count
//   2. Visual        — density, accent, capability flags, stream theme
//   3. Brand         — product name + subtitle
//
// Most tweaks flow through CSS variables on <body> so existing components
// don't have to change. The few exceptions (posture preset, brand text,
// live-ops initial state, approvals count) read from window.TWEAKS and
// re-render via a "tweaksTick" event we dispatch on every change.

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "posturePreset": "over-permissioned",
  "liveIntensity": 2,
  "livePaused": false,
  "liveView": "pipeline",
  "approvalsCount": 5,
  "pageState": "normal",
  "onboardingOpen": true,
  "onboardingStep": 0,
  "density": "cozy",
  "accent": "charcoal",
  "showFlags": true,
  "streamTheme": "dark",
  "brandName": "Agent Assembly",
  "brandSub": "acme · prod · v3.4.1"
}/*EDITMODE-END*/;

// --- presets ---------------------------------------------------------------

const ACCENTS = {
  charcoal: { ink: '#0e0e0e', ink2: '#2a2a2a' },
  indigo:   { ink: '#1e2a78', ink2: '#2d3a8c' },
  forest:   { ink: '#1d3a26', ink2: '#264a31' },
  rust:     { ink: '#7a2a14', ink2: '#8f3520' },
};

const DENSITIES = {
  compact: { fontSize: '13px', rowPad: '5px 8px',  pagePad: '16px 18px' },
  cozy:    { fontSize: '14px', rowPad: '7px 10px', pagePad: '22px 24px' },
  roomy:   { fontSize: '15px', rowPad: '10px 14px', pagePad: '28px 32px' },
};

// Posture presets: scale numbers on each agent. We keep the originals on
// window.__AGENTS_ORIG and rebuild AGENTS each time. Same for APPROVALS.
const POSTURE_PRESETS = {
  'calm': {
    label: 'Calm fleet',
    sub: 'low traffic, no incidents',
    transform: (a) => ({
      ...a,
      flagged: false,
      blocked24h: Math.round(a.blocked24h * 0.15),
      scrubbed24h: Math.round(a.scrubbed24h * 0.4),
      trust: Math.min(95, a.trust + 12),
    }),
    approvalsTake: 1,
  },
  'over-permissioned': {
    label: 'Over-permissioned',
    sub: 'current state · research-bot-04 alert',
    transform: (a) => a, // identity, this is the default authored data
    approvalsTake: null, // all
  },
  'incident': {
    label: 'Active incident',
    sub: 'spike in blocks, trust degrading',
    transform: (a) => ({
      ...a,
      flagged: a.id === 'research-bot-04' || a.trust < 70 || a.id === 'support-triage',
      blocked24h: Math.round(a.blocked24h * 2.4 + 30),
      scrubbed24h: Math.round(a.scrubbed24h * 1.8 + 8),
      trust: Math.max(20, a.trust - 18),
    }),
    approvalsTake: null,
  },
};

// --- apply visual tweaks via CSS vars + body classes -----------------------

function applyVisualTweaks(t) {
  const root = document.documentElement;
  const accent = ACCENTS[t.accent] || ACCENTS.charcoal;
  root.style.setProperty('--ink', accent.ink);
  root.style.setProperty('--ink-2', accent.ink2);

  const d = DENSITIES[t.density] || DENSITIES.cozy;
  root.style.setProperty('--tk-font', d.fontSize);
  root.style.setProperty('--tk-row-pad', d.rowPad);
  root.style.setProperty('--tk-page-pad', d.pagePad);

  document.body.classList.toggle('tk-no-flags', !t.showFlags);
  document.body.classList.toggle('tk-stream-light', t.streamTheme === 'light');
}

// --- apply data tweaks (posture preset + approvals count) ------------------

function applyDataTweaks(t) {
  if (!window.__AGENTS_ORIG) window.__AGENTS_ORIG = window.AGENTS.map((a) => ({ ...a }));
  if (!window.__APPROVALS_ORIG) window.__APPROVALS_ORIG = window.APPROVALS.slice();

  const preset = POSTURE_PRESETS[t.posturePreset] || POSTURE_PRESETS['over-permissioned'];
  window.AGENTS = window.__AGENTS_ORIG.map((a) => preset.transform(a));

  // approvals: pad or trim from the original list, looping if needed
  const orig = window.__APPROVALS_ORIG;
  const n = Math.max(0, Math.min(8, t.approvalsCount));
  const out = [];
  for (let i = 0; i < n; i++) {
    const src = orig[i % orig.length];
    out.push({ ...src, id: i < orig.length ? src.id : `${src.id}-${i}` });
  }
  window.APPROVALS = out;
}

// --- the panel --------------------------------------------------------------

function AssemblyTweaksPanel() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);

  // Apply visual + data on every change. Bump a tick so the App re-renders.
  React.useEffect(() => {
    applyVisualTweaks(t);
    applyDataTweaks(t);
    window.dispatchEvent(new CustomEvent('tweaksTick', { detail: t }));
  }, [t.posturePreset, t.density, t.accent, t.showFlags, t.streamTheme,
      t.approvalsCount, t.brandName, t.brandSub, t.pageState,
      t.onboardingOpen, t.onboardingStep,
      t.liveIntensity, t.livePaused, t.liveView]);

  // Keep brand + live-ops settings reachable globally for the few components
  // that read them directly (rail header, LiveOpsPage initial state).
  window.TWEAKS = t;

  return (
    <TweaksPanel title="Tweaks">
      <TweakSection label="Demo / Story" />
      <TweakRadio
        label="Posture"
        value={t.posturePreset}
        options={['calm', 'over-permissioned', 'incident']}
        onChange={(v) => setTweak('posturePreset', v)}
      />
      <div style={{ marginTop: -2, marginBottom: 4, fontSize: 10, color: 'rgba(41,38,27,.55)', fontFamily: 'JetBrains Mono, monospace' }}>
        {POSTURE_PRESETS[t.posturePreset]?.sub}
      </div>
      <TweakSlider
        label="Live intensity"
        value={t.liveIntensity}
        min={0.5} max={5} step={0.5} unit="×"
        onChange={(v) => setTweak('liveIntensity', v)}
      />
      <TweakToggle
        label="Live paused"
        value={t.livePaused}
        onChange={(v) => setTweak('livePaused', v)}
      />
      <TweakRadio
        label="Live view"
        value={t.liveView}
        options={['pipeline', 'moat']}
        onChange={(v) => setTweak('liveView', v)}
      />
      <TweakSlider
        label="Approvals"
        value={t.approvalsCount}
        min={0} max={8} step={1} unit=""
        onChange={(v) => setTweak('approvalsCount', v)}
      />
      <TweakSelect
        label="Page state"
        value={t.pageState}
        options={['normal', 'empty', 'loading', 'error']}
        onChange={(v) => setTweak('pageState', v)}
      />

      <TweakSection label="Onboarding" />
      <TweakToggle
        label="Show wizard"
        value={!!t.onboardingOpen}
        onChange={(v) => setTweak('onboardingOpen', v)}
      />
      <TweakSelect
        label="Jump to step"
        value={String(t.onboardingStep ?? 0)}
        options={['0', '1', '2', '3', '4']}
        onChange={(v) => { setTweak({ onboardingStep: parseInt(v, 10), onboardingOpen: true }); }}
      />
      <TweakButton
        label="Reset tenant (first-run mock)"
        onClick={() => {
          // Wipe agents to mimic a brand-new tenant; re-open wizard at step 0.
          window.AGENTS = [];
          window.APPROVALS = [];
          setTweak({ onboardingStep: 0, onboardingOpen: true });
        }}
      />

      <TweakSection label="Visual" />
      <TweakRadio
        label="Density"
        value={t.density}
        options={['compact', 'cozy', 'roomy']}
        onChange={(v) => setTweak('density', v)}
      />
      <TweakRadio
        label="Accent"
        value={t.accent}
        options={['charcoal', 'indigo', 'forest', 'rust']}
        onChange={(v) => setTweak('accent', v)}
      />
      <TweakToggle
        label="Capability flags"
        value={t.showFlags}
        onChange={(v) => setTweak('showFlags', v)}
      />
      <TweakRadio
        label="Stream theme"
        value={t.streamTheme}
        options={['dark', 'light']}
        onChange={(v) => setTweak('streamTheme', v)}
      />

      <TweakSection label="Brand" />
      <TweakText
        label="Product"
        value={t.brandName}
        placeholder="Agent Assembly"
        onChange={(v) => setTweak('brandName', v)}
      />
      <TweakText
        label="Subtitle"
        value={t.brandSub}
        placeholder="acme · prod · v3.4.1"
        onChange={(v) => setTweak('brandSub', v)}
      />
    </TweaksPanel>
  );
}

// Apply data + visual tweaks once at boot so the first render is correct
// even before the panel mounts.
applyVisualTweaks(TWEAK_DEFAULTS);
// applyDataTweaks runs in App after data.jsx loads — see below
window.__INITIAL_TWEAKS = TWEAK_DEFAULTS;

Object.assign(window, { AssemblyTweaksPanel, applyDataTweaks, applyVisualTweaks, TWEAK_DEFAULTS });
