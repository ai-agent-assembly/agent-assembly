import { CHART_CATEGORICAL_PALETTE } from './chartPalette'

const PALETTES = {
  categorical: CHART_CATEGORICAL_PALETTE,
}

export function useChartPalette(type: keyof typeof PALETTES): string[] {
  return PALETTES[type]
}
