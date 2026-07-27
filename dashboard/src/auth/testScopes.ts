import type { Scope } from './AuthContext'

/**
 * The scope set specs pass to `GrantScopes` when they just need a caller who
 * can write. Module-level so the array is referentially stable across renders,
 * and kept out of `GrantScopes.tsx` so that file exports only its component
 * (react-refresh/only-export-components).
 *
 * RBAC specs deliberately don't use a constant for the read-only case — they
 * pass `['read']` / `['write']` / `['admin']` inline, so the scope under test
 * is visible at the assertion rather than behind a name.
 */
export const WRITE_SCOPES: Scope[] = ['read', 'write']
