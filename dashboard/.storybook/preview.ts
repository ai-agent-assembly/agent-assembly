import type { Preview } from '@storybook/react'
import { withScopes } from './withScopes'
import '../src/styles.css'

const preview: Preview = {
  // One global scope provider rather than a per-story wrapper — see
  // `withScopes` for why it grants write, not admin (AAASM-5188).
  decorators: [withScopes],
  parameters: {
    backgrounds: {
      default: 'light',
    },
  },
}

export default preview
