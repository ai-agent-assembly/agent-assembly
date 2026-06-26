import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Tooltip } from './Tooltip'

describe('Tooltip', () => {
  it('hides the popup by default', () => {
    render(
      <Tooltip content="more info">
        <button type="button">target</button>
      </Tooltip>,
    )
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'target' })).toBeInTheDocument()
  })

  it('forces the popup visible when open is true', () => {
    render(
      <Tooltip content="forced" open>
        <span>anchor</span>
      </Tooltip>,
    )
    expect(screen.getByRole('tooltip')).toHaveTextContent('forced')
  })

  it('reveals the popup on hover and hides it on mouse leave', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip content="hover text">
        <span>anchor</span>
      </Tooltip>,
    )
    const wrapper = screen.getByText('anchor').parentElement as HTMLElement
    await user.hover(wrapper)
    expect(screen.getByRole('tooltip')).toHaveTextContent('hover text')
    await user.unhover(wrapper)
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('reveals the popup on focus and hides it on blur', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip content="focus text">
        <button type="button">anchor</button>
      </Tooltip>,
    )
    await user.tab()
    expect(screen.getByRole('tooltip')).toHaveTextContent('focus text')
    await user.tab()
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })
})
