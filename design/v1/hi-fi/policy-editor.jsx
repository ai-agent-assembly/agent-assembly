/* global React */
/* ============================================================
   Policy editor — rich, interactive form
   Turn 4: clause-level interaction (popover selects, verb toggle,
           action switch, draft state, dirty tracking)
   Turn 5: conditional sub-clauses (narrow paths chips, exceptions,
           approver settings, scrub preset, time-window, severity)
   Turn 6: validation panel + DSL preview + diff vs deployed +
           sticky save/simulate footer
   ============================================================ */
const { useState: usePE, useMemo: usePM, useEffect: usePEf, useRef: usePR } = React;

const RES_OPTS = ['gmail', 'gdrive', 's3', 'pg', 'shell', 'http', 'github', 'slack'];
const VERB_OPTS_PE = ['read', 'write', 'delete', 'exec'];
const ACTION_OPTS_PE = [
  { id: 'allow',           label: 'allow',        hint: 'pass through' },
  { id: 'narrow',          label: 'narrow',       hint: 'restrict scope' },
  { id: 'approval',        label: 'approval',     hint: 'human review' },
  { id: 'scrub-then-allow',label: 'scrub→allow',  hint: 'redact PII first' },
  { id: 'deny',            label: 'deny',         hint: 'block' },
];
const COND_PRESETS = [
  'always',
  'recipient not in @acme.com',
  'host in allowlist',
  'path matches customer-pii/*',
  'table contains PII columns',
  '2-person review required',
  'amount < $100',
  'business hours only',
];
const SCRUB_PRESETS = ['emails', 'phone numbers', 'SSN', 'credit cards', 'API keys', 'IP addresses', 'names'];

// -------------------------------------------------------------
// Popover — small click-to-open menu anchored to its trigger
// -------------------------------------------------------------
function Popover({ trigger, children, width = 220, align = 'left' }) {
  const [open, setOpen] = usePE(false);
  const ref = usePR(null);
  usePEf(() => {
    if (!open) return;
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);
  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-flex' }}>
      <span onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}>{trigger}</span>
      {open && (
        <div className="pop" style={{ width, [align === 'right' ? 'right' : 'left']: 0 }} onClick={(e) => e.stopPropagation()}>
          {typeof children === 'function' ? children(() => setOpen(false)) : children}
        </div>
      )}
    </span>
  );
}

function PopItem({ active, danger, onClick, children, hint }) {
  return (
    <div className={`pop-item ${active ? 'active' : ''} ${danger ? 'danger' : ''}`} onClick={onClick}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ width: 10, fontSize: 9 }}>{active ? '●' : ''}</span>
        <span style={{ flex: 1 }}>{children}</span>
      </div>
      {hint && <div className="pop-hint">{hint}</div>}
    </div>
  );
}

// -------------------------------------------------------------
// Editable chip list (paths, recipients, exceptions)
// -------------------------------------------------------------
function ChipList({ values, placeholder, onChange, mono = true, max = 8 }) {
  const [draft, setDraft] = usePE('');
  const add = () => {
    const v = draft.trim();
    if (!v) return;
    if (values.includes(v)) { setDraft(''); return; }
    onChange([...values, v]);
    setDraft('');
  };
  const remove = (i) => onChange(values.filter((_, idx) => idx !== i));
  return (
    <div className="chiplist">
      {values.map((v, i) => (
        <span key={i} className={`chip-edit ${mono ? 'mono' : ''}`}>
          {v}
          <span className="chip-x" onClick={() => remove(i)}>×</span>
        </span>
      ))}
      {values.length < max && (
        <input
          className="chip-input"
          value={draft}
          placeholder={placeholder}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); }
            if (e.key === 'Backspace' && !draft && values.length) remove(values.length - 1);
          }}
          onBlur={add}
        />
      )}
    </div>
  );
}

// -------------------------------------------------------------
// Verb toggle group — multi-select
// -------------------------------------------------------------
function VerbToggle({ value, onChange, danger }) {
  return (
    <div className="verbs">
      {VERB_OPTS_PE.map((v) => {
        const on = value.includes(v);
        const cls = on ? (danger ? 'on-danger' : 'on') : '';
        return (
          <span
            key={v}
            className={`verb ${cls}`}
            onClick={() => onChange(on ? value.filter((x) => x !== v) : [...value, v])}
          >{v}</span>
        );
      })}
    </div>
  );
}

// -------------------------------------------------------------
// Action picker — segmented, with hint
// -------------------------------------------------------------
function ActionPicker({ value, onChange }) {
  return (
    <div className="action-picker">
      {ACTION_OPTS_PE.map((a) => (
        <div
          key={a.id}
          className={`act act-${a.id} ${value === a.id ? 'on' : ''}`}
          onClick={() => onChange(a.id)}
          title={a.hint}
        >{a.label}</div>
      ))}
    </div>
  );
}

// -------------------------------------------------------------
// Default narrow paths per resource
// -------------------------------------------------------------
const DEFAULT_NARROW = {
  s3: ['s3://reports/*'],
  http: ['allowlist.acme.io', 'api.internal'],
  gmail: ['gmail/labels/INBOX/*'],
  gdrive: ['gdrive/shared/team-research/*'],
  github: ['github.com/acme/research/*'],
  pg: ['pg.public.reports'],
  shell: ['shell:python report.py'],
  slack: ['slack/channels/research'],
};

// -------------------------------------------------------------
// One rule card — fully interactive
// -------------------------------------------------------------
function RuleCard({ rule, idx, onPatch, onDup, onRemove, original }) {
  const changed = !original || JSON.stringify(rule) !== JSON.stringify(original);
  const danger = rule.action === 'deny';

  // Sub-clause defaults migrated lazily
  const narrow = rule.narrowPaths ?? (rule.action === 'narrow' ? DEFAULT_NARROW[rule.resource] || [] : []);
  const exceptions = rule.exceptions ?? [];
  const approver = rule.approver ?? { who: 'security-oncall', nOfM: '1-of-1', sla: '30m' };
  const scrub = rule.scrubFields ?? ['emails', 'phone numbers'];
  const window = rule.timeWindow ?? 'always';
  const severity = rule.severity ?? (danger ? 'block' : 'warn');

  return (
    <div className={`rule-card ${changed ? 'rule-dirty' : ''}`}>
      <div className="rule-card-head">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="rule-num">R{idx + 1}</div>
          {changed && <span className="dot-dirty" title="unsaved change" />}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button className="btn btn-sm" onClick={onDup}>duplicate</button>
          <button className="btn btn-sm" onClick={onRemove}>remove</button>
        </div>
      </div>

      {/* WHEN */}
      <div className="clause">
        <div className="clause-key">when</div>
        <div className="clause-row">
          <span className="clause-label">resource is</span>
          <Popover trigger={<span className="select select-em">{rule.resource}</span>} width={170}>
            {(close) => (
              <div>
                {RES_OPTS.map((r) => (
                  <PopItem key={r} active={r === rule.resource} onClick={() => { onPatch({ resource: r, narrowPaths: undefined }); close(); }}>{r}</PopItem>
                ))}
              </div>
            )}
          </Popover>
          <span className="clause-label">and verb is</span>
          <VerbToggle value={rule.verb} danger={danger} onChange={(v) => onPatch({ verb: v })} />
        </div>
      </div>

      {/* IF — conditions stack */}
      <div className="clause">
        <div className="clause-key">if</div>
        <div className="clause-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4 }}>
          <ConditionList
            value={Array.isArray(rule.condition) ? rule.condition : [rule.condition || 'always']}
            onChange={(c) => onPatch({ condition: c.length === 1 ? c[0] : c })}
          />
        </div>
      </div>

      {/* THEN */}
      <div className="clause">
        <div className="clause-key">then</div>
        <div className="clause-row">
          <ActionPicker value={rule.action} onChange={(a) => onPatch({ action: a })} />
        </div>
      </div>

      {/* Conditional sub-clauses based on action */}
      {rule.action === 'narrow' && (
        <div className="clause sub-clause">
          <div className="clause-key">narrow to</div>
          <div className="clause-row" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
            <ChipList
              values={narrow}
              placeholder={`add path for ${rule.resource}…`}
              onChange={(p) => onPatch({ narrowPaths: p })}
            />
            <div className="clause-help">Calls outside these patterns will be denied. Glob patterns ok ({'*'}).</div>
          </div>
        </div>
      )}

      {rule.action === 'approval' && (
        <div className="clause sub-clause">
          <div className="clause-key">approver</div>
          <div className="clause-row">
            <Popover trigger={<span className="select">who: {approver.who}</span>}>
              {(close) => ['security-oncall', 'data-platform-lead', 'agent-owner', 'sre-rotation', 'finance-head'].map((w) => (
                <PopItem key={w} active={w === approver.who} onClick={() => { onPatch({ approver: { ...approver, who: w } }); close(); }}>{w}</PopItem>
              ))}
            </Popover>
            <Popover trigger={<span className="select">{approver.nOfM}</span>} width={140}>
              {(close) => ['1-of-1', '1-of-2', '2-of-2', '2-of-3'].map((n) => (
                <PopItem key={n} active={n === approver.nOfM} onClick={() => { onPatch({ approver: { ...approver, nOfM: n } }); close(); }}>{n}</PopItem>
              ))}
            </Popover>
            <Popover trigger={<span className="select">SLA: {approver.sla}</span>} width={140}>
              {(close) => ['5m', '15m', '30m', '1h', '4h', '24h'].map((s) => (
                <PopItem key={s} active={s === approver.sla} onClick={() => { onPatch({ approver: { ...approver, sla: s } }); close(); }}>{s}</PopItem>
              ))}
            </Popover>
            <span className="clause-help">timeout → fall through to <b>deny</b></span>
          </div>
        </div>
      )}

      {rule.action === 'scrub-then-allow' && (
        <div className="clause sub-clause">
          <div className="clause-key">scrub</div>
          <div className="clause-row" style={{ flexWrap: 'wrap' }}>
            {SCRUB_PRESETS.map((s) => {
              const on = scrub.includes(s);
              return (
                <span key={s} className={`tag-toggle ${on ? 'on' : ''}`}
                  onClick={() => onPatch({ scrubFields: on ? scrub.filter((x) => x !== s) : [...scrub, s] })}>
                  {on ? '✓ ' : '+ '}{s}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Exceptions — available for any non-allow action */}
      {rule.action !== 'allow' && (
        <div className="clause sub-clause">
          <div className="clause-key">except</div>
          <div className="clause-row" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
            <ChipList
              values={exceptions}
              placeholder="add allow-list entry…"
              onChange={(e) => onPatch({ exceptions: e })}
            />
            <div className="clause-help">{exceptions.length === 0 ? 'No exceptions — rule applies universally.' : `${exceptions.length} call${exceptions.length === 1 ? '' : 's'} matching these will pass through unaffected.`}</div>
          </div>
        </div>
      )}

      {/* Time window + severity row */}
      <div className="clause">
        <div className="clause-key">window</div>
        <div className="clause-row">
          <Popover trigger={<span className="select">{window}</span>} width={170}>
            {(close) => ['always', 'business hours', 'after hours', 'weekdays', 'on-call hours'].map((w) => (
              <PopItem key={w} active={w === window} onClick={() => { onPatch({ timeWindow: w }); close(); }}>{w}</PopItem>
            ))}
          </Popover>
          <span className="clause-label">severity</span>
          {['warn', 'block'].map((s) => (
            <span key={s} className={`pill ${severity === s ? `pill-on pill-${s}` : ''}`} onClick={() => onPatch({ severity: s })}>{s}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// -------------------------------------------------------------
// Condition list — stack of conditions w/ AND between
// -------------------------------------------------------------
function ConditionList({ value, onChange }) {
  return (
    <div className="cond-stack">
      {value.map((c, i) => (
        <div key={i} className="cond-row">
          {i > 0 && <span className="cond-and">AND</span>}
          <Popover trigger={<span className="select">{c}</span>} width={260}>
            {(close) => (
              <div>
                {COND_PRESETS.map((p) => (
                  <PopItem key={p} active={p === c} onClick={() => { const nv = [...value]; nv[i] = p; onChange(nv); close(); }}>{p}</PopItem>
                ))}
                <div className="pop-divider" />
                <PopItem onClick={() => { onChange(value.filter((_, x) => x !== i)); close(); }} danger>remove condition</PopItem>
              </div>
            )}
          </Popover>
        </div>
      ))}
      <span className="add-clause" onClick={() => onChange([...value, 'always'])}>+ add condition</span>
    </div>
  );
}

// -------------------------------------------------------------
// DSL preview — renders the draft as a Rego-flavoured snippet
// -------------------------------------------------------------
function dslFor(draft) {
  const lines = [];
  lines.push(`policy "${draft.id}" {`);
  lines.push(`  name    = "${draft.name}"`);
  lines.push(`  scope   = "${draft.scope}"`);
  lines.push(`  version = "${draft.version}"`);
  lines.push(``);
  draft.rules.forEach((r, i) => {
    lines.push(`  rule R${i + 1} {`);
    lines.push(`    when   resource == "${r.resource}" and verb in [${r.verb.map((v) => `"${v}"`).join(', ') || '/* none */'}]`);
    const conds = Array.isArray(r.condition) ? r.condition : [r.condition || 'always'];
    lines.push(`    if     ${conds.map((c) => `"${c}"`).join(' and ')}`);
    lines.push(`    then   ${r.action}`);
    if (r.action === 'narrow' && r.narrowPaths?.length) {
      r.narrowPaths.forEach((p) => lines.push(`      narrow_to "${p}"`));
    }
    if (r.action === 'approval' && r.approver) {
      lines.push(`      approver { who="${r.approver.who}" n_of_m="${r.approver.nOfM}" sla="${r.approver.sla}" }`);
    }
    if (r.action === 'scrub-then-allow' && r.scrubFields?.length) {
      lines.push(`      scrub [${r.scrubFields.map((s) => `"${s}"`).join(', ')}]`);
    }
    if (r.exceptions?.length) {
      r.exceptions.forEach((e) => lines.push(`      except "${e}"`));
    }
    if (r.timeWindow && r.timeWindow !== 'always') lines.push(`      window "${r.timeWindow}"`);
    lines.push(`      severity ${r.severity || 'block'}`);
    lines.push(`  }`);
    if (i < draft.rules.length - 1) lines.push(``);
  });
  lines.push(`}`);
  return lines.join('\n');
}

// -------------------------------------------------------------
// Validation — surfaces errors / warnings against the draft
// -------------------------------------------------------------
function validate(draft) {
  const issues = [];
  const seen = new Map();
  draft.rules.forEach((r, i) => {
    const id = `R${i + 1}`;
    if (!r.verb || r.verb.length === 0) issues.push({ severity: 'error', rule: id, msg: 'no verbs selected — rule will never fire' });
    if (r.action === 'narrow' && (!r.narrowPaths || r.narrowPaths.length === 0)) {
      issues.push({ severity: 'error', rule: id, msg: 'action is narrow but no paths defined' });
    }
    if (r.action === 'scrub-then-allow' && (!r.scrubFields || r.scrubFields.length === 0)) {
      issues.push({ severity: 'warn', rule: id, msg: 'scrub-then-allow with no fields = full passthrough' });
    }
    (r.verb || []).forEach((v) => {
      const k = `${r.resource}:${v}`;
      if (seen.has(k)) issues.push({ severity: 'warn', rule: id, msg: `${k} also covered by R${seen.get(k) + 1} — first match wins` });
      else seen.set(k, i);
    });
    if (r.action === 'deny' && r.exceptions?.length > 4) {
      issues.push({ severity: 'info', rule: id, msg: `${r.exceptions.length} exceptions on a deny rule — consider narrow instead` });
    }
  });
  if (draft.rules.length === 0) issues.push({ severity: 'error', rule: '—', msg: 'policy has no rules' });
  return issues;
}

// -------------------------------------------------------------
// Main editor
// -------------------------------------------------------------
function PolicyEditor({ policy, openSimulate, toast }) {
  const [draft, setDraft] = usePE(() => clone(policy));
  const [showPreview, setShowPreview] = usePE(false);
  const [viewMode, setViewMode] = usePE('form'); // form | dsl
  usePEf(() => { setDraft(clone(policy)); }, [policy.id]);

  const original = usePM(() => clone(policy), [policy.id]);
  const dirty = usePM(() => JSON.stringify(draft) !== JSON.stringify(original), [draft, original]);
  const issues = usePM(() => validate(draft), [draft]);
  const errCount = issues.filter((i) => i.severity === 'error').length;
  const warnCount = issues.filter((i) => i.severity === 'warn').length;

  const patchRule = (i, patch) =>
    setDraft((d) => ({ ...d, rules: d.rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r)) }));
  const dupRule = (i) =>
    setDraft((d) => {
      const rules = [...d.rules];
      rules.splice(i + 1, 0, clone(rules[i]));
      return { ...d, rules };
    });
  const removeRule = (i) => setDraft((d) => ({ ...d, rules: d.rules.filter((_, idx) => idx !== i) }));
  const addRule = () =>
    setDraft((d) => ({
      ...d,
      rules: [...d.rules, { resource: 'gmail', verb: ['read'], action: 'allow', condition: 'always', severity: 'warn' }],
    }));

  const reset = () => { setDraft(clone(policy)); toast && toast('Reverted to deployed version'); };
  const save = () => { toast && toast(`Saved draft · ${draft.rules.length} rules · ${dirty ? 'unsaved changes' : 'no changes'}`); };

  return (
    <>
      <div className="pane-head">
        <div>
          <div className="pane-title">editor</div>
          <div style={{ fontSize: 13, fontWeight: 600, marginTop: 2, display: 'flex', alignItems: 'center', gap: 8 }}>
            {policy.id} · {policy.name}
            {dirty && <span className="chip chip-warn">draft · unsaved</span>}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span className={`chip chip-${policy.status === 'active' ? 'ok' : 'warn'}`}>{policy.status}</span>
          <span className="chip">{policy.version}</span>
          <div className="seg">
            <span className={`seg-i ${viewMode === 'form' ? 'on' : ''}`} onClick={() => setViewMode('form')}>form</span>
            <span className={`seg-i ${viewMode === 'dsl' ? 'on' : ''}`} onClick={() => setViewMode('dsl')}>DSL</span>
          </div>
        </div>
      </div>

      <div className="builder">
        {policy.status === 'proposed' && (
          <div className="callout">
            <div className="callout-title">⚠ draft policy</div>
            This narrows <b>research-bot-04</b> after the over-permissioning audit. Run simulate to see impact before rollout.
          </div>
        )}

        {viewMode === 'form' ? (
          <>
            {/* Scope card — read-only summary */}
            <div className="rule-card">
              <div className="rule-card-head">
                <div className="rule-card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="rule-num" style={{ background: 'transparent', color: 'var(--ink-4)' }}>·</span>
                  Scope
                </div>
              </div>
              <div className="clause">
                <div className="clause-key">applies to</div>
                <div className="clause-row">
                  <Popover trigger={<span className="select select-em">{draft.scope}</span>} width={260}>
                    {(close) => (
                      <div>
                        <PopItem active onClick={close}>{draft.scope}</PopItem>
                        <div className="pop-divider" />
                        <PopItem onClick={close}>+ add owner / framework / tag…</PopItem>
                      </div>
                    )}
                  </Popover>
                  <span className="clause-label">in</span>
                  <span className="select select-em">prod</span>
                  <span className="select">staging</span>
                </div>
              </div>
            </div>

            {draft.rules.map((r, i) => (
              <RuleCard
                key={i}
                rule={r}
                idx={i}
                original={original.rules[i]}
                onPatch={(p) => patchRule(i, p)}
                onDup={() => dupRule(i)}
                onRemove={() => removeRule(i)}
              />
            ))}

            <button className="btn" onClick={addRule} style={{ marginTop: 4 }}>+ add rule</button>

            {/* Validation panel */}
            <div className="validation">
              <div className="validation-head">
                <div className="section-title" style={{ margin: 0 }}>validation</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <span className={`vchip ${errCount ? 'err' : ''}`}>{errCount} errors</span>
                  <span className={`vchip ${warnCount ? 'warn' : ''}`}>{warnCount} warnings</span>
                </div>
              </div>
              {issues.length === 0 ? (
                <div className="vrow vrow-ok"><span className="vbadge ok">✓</span>policy is valid · ready to simulate</div>
              ) : (
                issues.map((iss, k) => (
                  <div key={k} className={`vrow vrow-${iss.severity}`}>
                    <span className={`vbadge ${iss.severity}`}>{iss.severity === 'error' ? '✕' : iss.severity === 'warn' ? '!' : 'i'}</span>
                    <span className="vrule">{iss.rule}</span>
                    <span>{iss.msg}</span>
                  </div>
                ))
              )}
            </div>
          </>
        ) : (
          <pre className="dsl">{dslFor(draft)}</pre>
        )}

        <div className="builder-foot">
          <div style={{ fontSize: 12, color: 'var(--ink-3)' }}>
            {dirty
              ? <>{rulesChangedCount(draft, original)} rule{rulesChangedCount(draft, original) === 1 ? '' : 's'} modified · run simulate to preview impact</>
              : policy.status === 'proposed'
                ? <>Draft — never deployed</>
                : <>Active since {policy.version} · {policy.hits24h} hits/24h</>}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {dirty && <button className="btn" onClick={reset}>↶ revert</button>}
            <button className="btn" onClick={save}>Save draft</button>
            <button className={`btn btn-primary ${errCount ? 'btn-disabled' : ''}`} onClick={errCount ? () => toast && toast(`Fix ${errCount} error${errCount===1?'':'s'} first`) : openSimulate}>▸ Simulate impact</button>
          </div>
        </div>
      </div>
    </>
  );
}

function clone(o) { return JSON.parse(JSON.stringify(o)); }
function rulesChangedCount(a, b) {
  let n = Math.abs((a.rules?.length || 0) - (b.rules?.length || 0));
  const len = Math.min(a.rules.length, b.rules.length);
  for (let i = 0; i < len; i++) if (JSON.stringify(a.rules[i]) !== JSON.stringify(b.rules[i])) n++;
  return n;
}

Object.assign(window, { PolicyEditor });
