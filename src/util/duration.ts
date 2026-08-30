// `src/util/duration.ts` — M8.2: converts the `\d+[smhd]` duration strings
// `src/config/schema.ts`'s `DURATION_RE` already validates (today only for
// `vm.max-session`) into a millisecond count, so a consumer (the watchdog
// wiring in `src/vm/session.ts`) has an actual number to hand `setTimeout`.
//
// Deliberately its own tiny module rather than folded into `session.ts` or
// `watchdog.ts` directly: `session.ts` already owns comparable raw-to-
// validated conversions itself (e.g. `toGlobRules`), and this is the same
// kind of narrow, independently-testable parsing step, worth a file of its
// own so its unit tests don't have to go through either of those modules.
//
// This module does not re-validate against `src/config/schema.ts`'s
// `DURATION_RE` (no import from `src/config/` — matching `session.ts`'s own
// documented decoupling from the config system). It has its own regex here,
// which must stay in sync with `DURATION_RE` by construction (same four
// suffixes, same "one or more digits" shape) but is not literally shared code
// — there is no third module either would import it from without inventing
// one.
const DURATION_FORMAT_RE = /^(\d+)([smhd])$/;

type DurationUnit = "s" | "m" | "h" | "d";

const UNIT_MS: Record<DurationUnit, number> = {
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/**
 * Thrown by `parseDuration` for any input that doesn't match `\d+[smhd]`.
 * Defensive, not expected in normal operation: by the time this is called on
 * real config data, `src/config/schema.ts`'s `DURATION_RE` has already
 * validated the format at parse time. A direct caller (including this
 * module's own tests) can still pass anything, so this is a real, reachable
 * error path, not dead code.
 */
export class DurationParseError extends Error {
  readonly input: string;

  constructor(input: string) {
    super(`corb: invalid duration '${input}' (expected a format like '30s', '5m', '4h', or '1d')`);
    this.name = "DurationParseError";
    this.input = input;
  }
}

/** Converts a `\d+[smhd]` duration string into milliseconds. Throws `DurationParseError` for anything else. */
export function parseDuration(text: string): number {
  const match = DURATION_FORMAT_RE.exec(text);
  if (!match) {
    throw new DurationParseError(text);
  }
  const [, digits, unit] = match;
  const value = Number(digits);
  return value * UNIT_MS[unit as DurationUnit];
}
