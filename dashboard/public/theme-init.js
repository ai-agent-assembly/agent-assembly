/**
 * Theme initialization script — CSP-compliant external version.
 *
 * This script applies the saved or OS-preferred theme before first paint to
 * avoid a flash of the wrong theme. It mirrors getInitialTheme() in
 * src/theme/useTheme.ts.
 *
 * IMPORTANT: Keep this logic in sync with useTheme.ts. This file exists solely
 * to satisfy strict Content-Security-Policy requirements that forbid inline
 * scripts.
 */
(function () {
  'use strict';
  try {
    var THEME_STORAGE_KEY = 'aa-dashboard-theme';
    var stored = localStorage.getItem(THEME_STORAGE_KEY);
    var theme =
      stored === 'light' || stored === 'dark'
        ? stored
        : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light';
    document.documentElement.setAttribute('data-theme', theme);
  } catch (e) {
    // no-op: theme will be applied by React on mount
  }
})();
