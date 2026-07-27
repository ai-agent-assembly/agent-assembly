import { absent, isKnown, known, propagateAbsence, type Certain } from '../../lib/truthfulness'

/**
 * The payload as pretty-printed JSON, or an explicit absence.
 *
 * AAASM-5165 — this replaces `JSON.stringify(payload, null, 2) ?? 'null'`,
 * which put the four-character string `null` into the preview body along two
 * separate routes:
 *
 *  - `JSON.stringify(undefined)` returns `undefined` (the value, not the text),
 *    so the `?? 'null'` fallback fired and printed the word;
 *  - `JSON.stringify(null)` returns the *string* `"null"`, so the fallback was
 *    not even needed — the word went straight to the DOM.
 *
 * Either way the operator read "null" as the recorded payload content. A JSON
 * `null` is the absence of a payload, not a payload whose content is the word
 * null, so both routes now produce an absence the surface can label.
 *
 * Lives in its own module rather than beside `RedactionPreview` so that file
 * exports only its component (`react-refresh/only-export-components`).
 */
export function previewJson(payload: Certain<unknown>): Certain<string> {
  if (!isKnown(payload)) return propagateAbsence(payload)
  if (payload.value === null || payload.value === undefined) {
    return absent<string>('unknown', 'No payload content was recorded for this event')
  }
  const formatted = JSON.stringify(payload.value, null, 2)
  // A function, a symbol, or an object whose `toJSON` returns undefined has no
  // JSON representation at all; `stringify` reports that by returning
  // `undefined` rather than by throwing.
  if (formatted === undefined) {
    return absent<string>('unknown', 'This payload has no JSON representation')
  }
  return known(formatted)
}
