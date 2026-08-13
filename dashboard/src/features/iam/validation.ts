// Bounded quantifiers (RFC-5321 length caps) keep this linear and avoid the
// polynomial backtracking the unbounded `+` form triggers on inputs like
// "a@" + many non-dot chars (the `.` overlaps `[^\s@]`). See typescript:S5852.
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,251}\.[^\s@]{1,63}$/

export function isValidEmail(value: string): boolean {
  return EMAIL_RE.test(value.trim())
}
