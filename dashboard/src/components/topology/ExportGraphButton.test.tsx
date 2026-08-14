import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { ExportGraphButton } from './ExportGraphButton'

describe('ExportGraphButton', () => {
  it('toggles the menu and fires the SVG / JSON callbacks', async () => {
    const onExportSvg = vi.fn()
    const onExportJson = vi.fn()
    render(<ExportGraphButton onExportSvg={onExportSvg} onExportJson={onExportJson} />)

    // Menu closed initially.
    expect(screen.queryByTestId('topology-export-menu')).toBeNull()

    await userEvent.click(screen.getByTestId('topology-export-button'))
    expect(screen.getByTestId('topology-export-menu')).toBeInTheDocument()

    await userEvent.click(screen.getByTestId('topology-export-svg'))
    expect(onExportSvg).toHaveBeenCalledTimes(1)
    // Menu closes after choosing.
    expect(screen.queryByTestId('topology-export-menu')).toBeNull()

    await userEvent.click(screen.getByTestId('topology-export-button'))
    await userEvent.click(screen.getByTestId('topology-export-json'))
    expect(onExportJson).toHaveBeenCalledTimes(1)
  })

  it('closes the menu on an outside click', async () => {
    render(
      <div>
        <button data-testid="outside">outside</button>
        <ExportGraphButton onExportSvg={vi.fn()} onExportJson={vi.fn()} />
      </div>,
    )
    await userEvent.click(screen.getByTestId('topology-export-button'))
    expect(screen.getByTestId('topology-export-menu')).toBeInTheDocument()
    await userEvent.click(screen.getByTestId('outside'))
    expect(screen.queryByTestId('topology-export-menu')).toBeNull()
  })
})
