// `src/util/redact.ts` — M3.1: a defense-in-depth text scrubber for
// `src/policy/audit.ts`. Not the primary redaction mechanism — per
// `docs/design.md` §6, a channel's `subject`/`reason` is supposed to only
// ever be *constructed* from safe material in the first place (e.g. the
// HTTP channel's `safeSubject()`, added in a later item, which returns
// exactly `${method} ${hostname}${pathname}` and is structurally incapable
// of including headers or query strings). This module exists so the audit
// writer can *additionally* scrub any live secret value it's told about
// before a line ever reaches disk — a second, independent safety net, in
// the same "belt and suspenders" spirit as `src/config/guestpaths.ts`'s two
// independent mount-safety checks.

const REDACTED_PLACEHOLDER = "[REDACTED]";

/**
 * Replaces every occurrence of every non-empty string in `secrets` with
 * `[REDACTED]`. Empty-string secrets are ignored — matching one everywhere
 * would corrupt every character of `text`. An empty `secrets` list is a
 * no-op: `text` is returned unchanged, not rejected.
 *
 * Exact literal substring matching only, not a pattern: each secret is
 * found and replaced via `split`/`join` rather than a `RegExp`, so
 * metacharacters in a secret's own content are never interpreted as pattern
 * syntax, and every (non-overlapping, left-to-right) occurrence of a
 * repeated secret within `text` is replaced, not just the first.
 */
export function redactKnownSecrets(text: string, secrets: readonly string[]): string {
  const nonEmptySecrets = secrets.filter((secret) => secret.length > 0);
  if (nonEmptySecrets.length === 0) {
    return text;
  }

  let result = text;
  for (const secret of nonEmptySecrets) {
    result = result.split(secret).join(REDACTED_PLACEHOLDER);
  }
  return result;
}
