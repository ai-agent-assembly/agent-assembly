import { CHART_CATEGORICAL_PALETTE, CHART_COLORBLIND_PALETTE } from './chartPalette'

const PALETTES = {
  categorical: CHART_CATEGORICAL_PALETTE,
  colorblind: CHART_COLORBLIND_PALETTE,
}

export function useChartPalette(type: keyof typeof PALETTES): string[] {
  return PALETTES[type]
}
