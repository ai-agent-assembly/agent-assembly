import { FRAMEWORKS } from '../fixtures'
import type { FrameworkId, WizardState } from '../types'
import './Steps.css'

export interface Step1FrameworkProps {
  state: WizardState
  onChange: (framework: FrameworkId) => void
}

export function Step1Framework({ state, onChange }: Step1FrameworkProps) {
  return (
    <section data-testid="onboarding-step-framework">
      <h2 className="onb-body-title">Pick the framework you&apos;re enrolling.</h2>
      <p className="onb-body-sub">
        We support most agent runtimes. Your choice determines which SDK package and
        identity format we install in the next step.
      </p>
      <div className="onb-fw-grid" role="radiogroup" aria-label="agent framework">
        {FRAMEWORKS.map((fw) => {
          const selected = state.framework === fw.id
          return (
            <button
              key={fw.id}
              type="button"
              role="radio"
              aria-checked={selected}
              className={`onb-fw-card${selected ? ' is-selected' : ''}`}
              data-testid={`onboarding-framework-${fw.id}`}
              onClick={() => onChange(fw.id)}
            >
              <span className="onb-fw-radio" aria-hidden />
              <span className="onb-fw-glyph" aria-hidden>
                {fw.glyph}
              </span>
              <span className="onb-fw-info">
                <span className="onb-fw-name">{fw.name}</span>
                <span className="onb-fw-sub">{fw.sub}</span>
              </span>
              {fw.popular && <span className="onb-fw-pop">most common</span>}
            </button>
          )
        })}
      </div>
    </section>
  )
}
