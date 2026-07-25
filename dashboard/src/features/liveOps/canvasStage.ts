/**
 * Shared sizing helper for the Live Ops canvas visualizations
 * (`PipelineCanvas`, `CastleMoat`).
 *
 * The device-pixel-ratio + parent-rect measurement is identical for every
 * full-bleed canvas we draw, so it lives here once instead of being copied
 * into each component's `resize()`. The caller keeps its own logical
 * width/height state; this returns the CSS-pixel size it applied so the caller
 * can mirror it.
 */
export function sizeCanvasToParent(
  canvas: HTMLCanvasElement,
  ctx: CanvasRenderingContext2D,
  minWidth: number,
  minHeight: number,
): { width: number; height: number } {
  const ratio = window.devicePixelRatio || 1
  const host = canvas.parentElement
  const bounds = host
    ? host.getBoundingClientRect()
    : canvas.getBoundingClientRect()
  const width = Math.max(bounds.width || minWidth, minWidth)
  const height = Math.max(bounds.height || minHeight, minHeight)
  canvas.width = width * ratio
  canvas.height = height * ratio
  canvas.style.width = `${width}px`
  canvas.style.height = `${height}px`
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0)
  return { width, height }
}
