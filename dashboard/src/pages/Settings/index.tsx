// Settings shell — left-rail sub-navigation rendering the active child
// route in the main panel. Currently surfaces the Storage → Retention
// Policy entry (AAASM-1592 S-K); General and API Keys are placeholders
// for future sub-tickets so the IA shape is complete on landing.

import { NavLink, Outlet } from 'react-router-dom'
import './Settings.css'

interface SettingsNavEntry {
  id: string
  label: string
  to: string
  section?: string
}

const SETTINGS_NAV: SettingsNavEntry[] = [
  { id: 'general', label: 'General', to: '/settings/general' },
  { id: 'api-keys', label: 'API Keys', to: '/settings/api-keys' },
  {
    id: 'storage-retention',
    label: 'Retention Policy',
    to: '/settings/storage/retention',
    section: 'Storage',
  },
]

export function SettingsLayout() {
  return (
    <main className="settings-page" data-testid="settings-page">
      <aside className="settings-page__nav" data-testid="settings-nav">
        <h2 className="settings-page__nav-title">Settings</h2>
        <ul className="settings-page__nav-list">
          {SETTINGS_NAV.map((entry) => (
            <li key={entry.id}>
              {entry.section && (
                <div
                  className="settings-page__nav-section"
                  data-testid={`settings-nav-section-${entry.section.toLowerCase()}`}
                >
                  {entry.section}
                </div>
              )}
              <NavLink
                to={entry.to}
                className={({ isActive }) =>
                  `settings-page__nav-link${isActive ? ' settings-page__nav-link--active' : ''}`
                }
                data-testid={`settings-nav-link-${entry.id}`}
              >
                {entry.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </aside>
      <section className="settings-page__panel">
        <Outlet />
      </section>
    </main>
  )
}

export function SettingsGeneralPlaceholder() {
  return (
    <section data-testid="settings-general-placeholder">
      <h1>General</h1>
      <p>General workspace settings land in a follow-up sub-ticket.</p>
    </section>
  )
}

export function SettingsApiKeysPlaceholder() {
  return (
    <section data-testid="settings-api-keys-placeholder">
      <h1>API Keys</h1>
      <p>
        API key management already lives at <NavLink to="/identity">Identity</NavLink>; a Settings-scoped redirect
        consolidates the entry-point in a follow-up sub-ticket.
      </p>
    </section>
  )
}
