import { Component, type ErrorInfo, type ReactNode } from 'react'
import { ErrorState } from '../../components/states'

interface PanelErrorBoundaryProps {
  /** Human-readable panel name, surfaced in the fallback card. */
  panelName: string
  children: ReactNode
}

interface PanelErrorBoundaryState {
  error: Error | null
}

/**
 * Isolates a single analytics panel's render errors.
 *
 * Without a per-panel boundary, a malformed 200 response in one panel (e.g. a
 * timestamp outside JS Date range) throws during render and propagates up to the
 * AppShell boundary, blanking the ENTIRE Analytics view. Wrapping each panel here
 * degrades the failure to a single-panel error card while its siblings and the
 * page shell keep rendering (AAASM-4155).
 */
export class PanelErrorBoundary extends Component<
  PanelErrorBoundaryProps,
  PanelErrorBoundaryState
> {
  state: PanelErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): PanelErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[analytics] ${this.props.panelName} panel error:`, error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <ErrorState
          title={`${this.props.panelName} couldn't be displayed`}
          description="This panel hit an unexpected error. The rest of your analytics are unaffected."
          onRetry={() => this.setState({ error: null })}
          retryLabel="Try again"
        />
      )
    }
    return this.props.children
  }
}
