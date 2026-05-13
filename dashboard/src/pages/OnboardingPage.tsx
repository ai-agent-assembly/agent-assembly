import { Navigate, useNavigate } from 'react-router-dom'
import { OnboardingWizard } from '../features/onboarding/OnboardingWizard'
import {
  markGatewayConfigured,
  useGatewayConfiguredGuard,
} from '../features/onboarding/useGatewayConfiguredGuard'

export function OnboardingPage() {
  const navigate = useNavigate()
  const alreadyConfigured = useGatewayConfiguredGuard()

  if (alreadyConfigured) {
    return <Navigate to="/" replace />
  }

  const finish = () => {
    markGatewayConfigured()
    navigate('/', { replace: true })
  }

  return <OnboardingWizard onFinish={finish} onSkipAll={finish} />
}
