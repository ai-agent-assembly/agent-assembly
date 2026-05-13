import { useEffect } from 'react'
import { POLICY_PRESETS } from '../fixtures'
import type { PolicyPresetId, WizardState } from '../types'
import './Steps.css'

export interface Step4BaselinePolicyProps {
  state: WizardState
  onChange: (preset: PolicyPresetId) => void
}

export function Step4BaselinePolicy({ state, onChange }: Step4BaselinePolicyProps) {
  // Sensible default — the recommended preset is "read-only" per the hi-fi.
  useEffect(() => {
    if (!state.policyPreset) onChange('read-only')
  }, [state.policyPreset, onChange])

  const selectedId = state.policyPreset ?? 'read-only'
  const preset = POLICY_PRESETS.find((p) => p.id === selectedId) ?? POLICY_PRESETS[1]

  return (
    <section data-testid="onboarding-step-policy">
      <h2 className="onb-body-title">Pick a baseline policy.</h2>
      <p className="onb-body-sub">
        Every agent starts under this policy. You can refine per-agent rules in the
        Policy editor afterwards.
      </p>

      <div className="onb-pp-grid" role="radiogroup" aria-label="baseline policy">
        {POLICY_PRESETS.map((p) => {
          const selected = selectedId === p.id
          return (
            <button
              key={p.id}
              type="button"
              role="radio"
              aria-checked={selected}
              className={`onb-pp-card${selected ? ' is-selected' : ''}`}
              data-testid={`onboarding-policy-${p.id}`}
              onClick={() => onChange(p.id)}
            >
              <span className="onb-pp-name">{p.name}</span>
              <span className="onb-pp-sub">{p.sub}</span>
              <span className={`onb-pp-risk is-${p.risk}`}>risk · {p.risk}</span>
            </button>
          )
        })}
      </div>

      {preset && (
        <div className="onb-pp-preview" data-testid="onboarding-policy-preview">
          <div className="onb-pp-preview-h">{preset.name} · what this looks like</div>
          <p className="onb-pp-preview-desc">{preset.desc}</p>
          <div className="onb-pp-cols">
            <div>
              <div className="onb-pp-col-h">blocks</div>
              {preset.blocks.length === 0 ? (
                <div className="onb-pp-rule is-empty">— no blocking rules —</div>
              ) : (
                preset.blocks.map((b) => (
                  <div key={b} className="onb-pp-rule is-block">
                    {b}
                  </div>
                ))
              )}
            </div>
            <div>
              <div className="onb-pp-col-h">allows</div>
              {preset.allows.length === 0 ? (
                <div className="onb-pp-rule is-empty">— no allow rules —</div>
              ) : (
                preset.allows.map((a) => (
                  <div key={a} className="onb-pp-rule is-allow">
                    {a}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
