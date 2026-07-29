import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { BudgetTree } from './BudgetTree'
import type { BudgetTree as BudgetTreeData } from '../../features/costs/api'

const TREE: BudgetTreeData = {
  root: {
    id: 'acme',
    label: 'acme',
    kind: 'org',
    depth: 0,
    budget_limit_usd: '100',
    own_spend_usd: '0',
    subtree_spend_usd: '10.00',
    children: [
      {
        id: 'team-a',
        label: 'team-a',
        kind: 'team',
        depth: 1,
        budget_limit_usd: '50',
        own_spend_usd: '0',
        subtree_spend_usd: '8.00',
        children: [
          {
            id: 'root-a',
            label: 'root-a',
            kind: 'agent',
            depth: 2,
            budget_limit_usd: '20',
            own_spend_usd: '5.00',
            subtree_spend_usd: '8.00',
            governance_level: 'L0Discover',
            children: [
              {
                id: 'child-a',
                label: 'child-a',
                kind: 'agent',
                depth: 3,
                budget_limit_usd: '8',
                own_spend_usd: '3.00',
                subtree_spend_usd: '3.00',
                governance_level: 'L0Discover',
                children: [],
              },
            ],
          },
        ],
      },
      {
        id: 'team-b',
        label: 'team-b',
        kind: 'team',
        depth: 1,
        budget_limit_usd: '20',
        own_spend_usd: '0',
        subtree_spend_usd: '2.00',
        children: [],
      },
    ],
  },
}

describe('BudgetTree', () => {
  it('renders the org root and teams expanded by default, agents collapsed', () => {
    render(<BudgetTree data={TREE} isLoading={false} isError={false} />)
    expect(screen.getByTestId('budget-tree-grid')).toBeInTheDocument()
    // Org + teams + their root agents are visible; the sub-agent is hidden until
    // its parent agent row is expanded.
    expect(screen.getByTestId('budget-node-acme')).toBeInTheDocument()
    expect(screen.getByTestId('budget-node-team-a')).toBeInTheDocument()
    expect(screen.getByTestId('budget-node-root-a')).toBeInTheDocument()
    expect(screen.queryByTestId('budget-node-child-a')).not.toBeInTheDocument()
    // Kind badge and governance level surface on the agent row. The level is
    // shown in its two-char form (L0), with the full enum in the chip title
    // (AAASM-5172).
    expect(screen.getByTestId('budget-node-root-a')).toHaveAttribute('data-kind', 'agent')
    const govChips = screen.getAllByText('L0')
    expect(govChips.length).toBeGreaterThan(0)
    expect(govChips[0]).toHaveAttribute('title', 'L0Discover')
  })

  it('renders each governance level as its two-char tag', () => {
    const levels: BudgetTreeData = {
      root: {
        id: 'org',
        label: 'org',
        kind: 'org',
        depth: 0,
        budget_limit_usd: '100',
        own_spend_usd: '0',
        subtree_spend_usd: '0',
        children: [
          { id: 'e', label: 'e', kind: 'agent', depth: 1, budget_limit_usd: '10', own_spend_usd: '1', subtree_spend_usd: '1', governance_level: 'L2Enforce', children: [] },
          { id: 'n', label: 'n', kind: 'agent', depth: 1, budget_limit_usd: '10', own_spend_usd: '1', subtree_spend_usd: '1', governance_level: 'L3Native', children: [] },
        ],
      },
    }
    render(<BudgetTree data={levels} isLoading={false} isError={false} />)

    expect(screen.getByText('L2')).toHaveAttribute('title', 'L2Enforce')
    expect(screen.getByText('L3')).toHaveAttribute('title', 'L3Native')
    expect(screen.queryByText('L2Enforce')).not.toBeInTheDocument()
  })

  it('expands and collapses a node with children on click', async () => {
    const user = userEvent.setup()
    render(<BudgetTree data={TREE} isLoading={false} isError={false} />)

    // Expand: clicking the row's disclosure button reveals the sub-agent row.
    await user.click(screen.getByTestId('budget-toggle-root-a'))
    expect(screen.getByTestId('budget-node-child-a')).toBeInTheDocument()

    // Collapse: it disappears again.
    await user.click(screen.getByTestId('budget-toggle-root-a'))
    expect(screen.queryByTestId('budget-node-child-a')).not.toBeInTheDocument()
  })

  it('expands and collapses a node with children via the keyboard (Enter)', async () => {
    const user = userEvent.setup()
    render(<BudgetTree data={TREE} isLoading={false} isError={false} />)

    // The disclosure is a native <button>, so focus + Enter expands it.
    screen.getByTestId('budget-toggle-root-a').focus()
    await user.keyboard('{Enter}')
    expect(screen.getByTestId('budget-node-child-a')).toBeInTheDocument()

    // Enter again collapses it.
    screen.getByTestId('budget-toggle-root-a').focus()
    await user.keyboard('{Enter}')
    expect(screen.queryByTestId('budget-node-child-a')).not.toBeInTheDocument()
  })

  it('toggles a node with the Space key and exposes disclosure semantics', async () => {
    const user = userEvent.setup()
    render(<BudgetTree data={TREE} isLoading={false} isError={false} />)
    const toggle = screen.getByTestId('budget-toggle-root-a')

    // The disclosure is a native, focusable button reporting its expanded state.
    expect(toggle.tagName).toBe('BUTTON')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')

    // Space expands it.
    toggle.focus()
    await user.keyboard(' ')
    expect(screen.getByTestId('budget-node-child-a')).toBeInTheDocument()
    expect(screen.getByTestId('budget-toggle-root-a')).toHaveAttribute('aria-expanded', 'true')

    // Space again collapses it.
    screen.getByTestId('budget-toggle-root-a').focus()
    await user.keyboard(' ')
    expect(screen.queryByTestId('budget-node-child-a')).not.toBeInTheDocument()
    expect(screen.getByTestId('budget-toggle-root-a')).toHaveAttribute('aria-expanded', 'false')
  })

  it('renders leaf rows without a disclosure button', async () => {
    const user = userEvent.setup()
    render(<BudgetTree data={TREE} isLoading={false} isError={false} />)

    // Expand root-a so its leaf child renders; the leaf has no toggle control.
    await user.click(screen.getByTestId('budget-toggle-root-a'))
    expect(screen.getByTestId('budget-node-child-a')).toBeInTheDocument()
    expect(screen.queryByTestId('budget-toggle-child-a')).not.toBeInTheDocument()
  })

  it('shows the loading state', () => {
    render(<BudgetTree data={undefined} isLoading={true} isError={false} />)
    expect(screen.getByTestId('budget-tree-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('budget-tree-grid')).not.toBeInTheDocument()
  })

  it('shows the error state', () => {
    render(<BudgetTree data={undefined} isLoading={false} isError={true} />)
    expect(screen.getByTestId('budget-tree-error')).toBeInTheDocument()
  })

  it('shows the empty state when the root is null', () => {
    render(<BudgetTree data={{ root: null }} isLoading={false} isError={false} />)
    expect(screen.getByTestId('budget-tree-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('budget-tree-grid')).not.toBeInTheDocument()
  })

  it('dashes the subtree burn for a node with no configured limit', () => {
    // A node that has spent money but has no ceiling has no burn fraction to
    // report. It must read as an em-dash, never a fabricated 0.0% that scans as
    // a measured zero burn (AAASM-5172).
    const noLimit: BudgetTreeData = {
      root: {
        id: 'acme',
        label: 'acme',
        kind: 'org',
        depth: 0,
        budget_limit_usd: null,
        own_spend_usd: '12.00',
        subtree_spend_usd: '12.00',
        children: [],
      },
    }
    render(<BudgetTree data={noLimit} isLoading={false} isError={false} />)

    const row = screen.getByTestId('budget-node-acme')
    expect(row).toHaveTextContent('—')
    expect(row).not.toHaveTextContent('0.0%')
  })
})
