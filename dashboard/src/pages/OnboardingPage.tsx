import { useMemo } from 'react'
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
