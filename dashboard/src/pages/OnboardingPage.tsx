import { useEffect, useMemo, useRef } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useToast } from '../components/Toast'
import { OnboardingWizard } from '../features/onboarding/OnboardingWizard'
import {
  markGatewayConfigured,
  useGatewayConfiguredGuard,
} from '../features/onboarding/useGatewayConfiguredGuard'
import {
  clearWizardSession,
  resolveInitialSession,
  saveWizardSession,
} from '../features/onboarding/useWizardSession'

export function OnboardingPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const alreadyConfigured = useGatewayConfiguredGuard()

  // Hydrate the initial step + state once per mount; subsequent persistence
  // is driven by the wizard via onPersist.
  const initialSession = useMemo(() => resolveInitialSession(), [])

  // Say so when saved progress was dropped. Restarting an operator at step 1
  // with no explanation reads as the wizard having lost their work; the honest
  // account is that the stored session recorded claims this build withdrew.
  const notified = useRef(false)
  useEffect(() => {
    if (!initialSession.discarded || notified.current) return
    notified.current = true
    toast('Saved setup progress was discarded — it was recorded by an older build.', 'info')
  }, [initialSession.discarded, toast])

  if (alreadyConfigured) {
    return <Navigate to="/" replace />
  }

  const finishWith = (kind: 'finished' | 'skipped') => {
    markGatewayConfigured()
    clearWizardSession()
    if (kind === 'finished') {
      toast('Setup complete — welcome to Agent Assembly.', 'success')
    } else {
      toast('Onboarding skipped — you can re-run it from the Tweaks panel.', 'info')
    }
    navigate('/', { replace: true })
  }

  return (
    <OnboardingWizard
      initialStep={initialSession.step}
      initialState={initialSession.state}
      onPersist={(snapshot) => saveWizardSession(snapshot)}
      onFinish={() => finishWith('finished')}
      onSkipAll={() => finishWith('skipped')}
    />
  )
}
