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

/**
 * The largest delay Node's `setTimeout` can represent. Node stores a timer's
 * delay as a signed 32-bit integer internally, so `2**31 - 1` ms (≈24.8 days)
 * is the largest value that survives intact — anything past it doesn't
 * error, it silently clamps to a ~1ms timer (Node emits
 * `TimeoutOverflowWarning` on stderr but otherwise proceeds), firing almost
 * immediately instead of after the requested delay. `parseDuration` below
 * and `src/config/schema.ts`'s `vm.max-session` bound check both import this
 * single constant rather than each hard-coding the magic number.
 */
export const MAX_SETTIMEOUT_MS = 2_147_483_647; // 2**31 - 1

/**
 * Thrown by `parseDuration` when the parsed value, in milliseconds, exceeds
 * `MAX_SETTIMEOUT_MS`. `parseDuration`'s whole purpose (see the module
 * comment above) is handing a consumer "an actual number to hand
 * `setTimeout`" — a value that would silently break `setTimeout` is this
 * function failing its own stated contract, so it is rejected here rather
 * than returned.
 *
 * Defensive, not expected in normal operation: by the time this is called on
 * real `vm.max-session` config data, `src/config/schema.ts` has already
 * rejected an out-of-range value at parse time (the same reasoning
 * `DurationParseError` above already documents for the format check). A
 * direct caller can still pass anything, though — including this module's
 * own tests, and `corb gc --older-than` (`src/commands/gc.ts`), which calls
 * `parseDuration` directly and never goes through the config schema at all —
 * so this is a real, reachable error path, not dead code.
 */
export class DurationOverflowError extends Error {
  readonly input: string;
  readonly ms: number;

  constructor(input: string, ms: number) {
    super(
      `corb: duration '${input}' is ${ms}ms, too long for Node's setTimeout to represent (max ${MAX_SETTIMEOUT_MS}ms, ` +
        `≈24.8 days), so it would silently clamp to a ~1ms timer instead of honoring the requested delay`,
    );
    this.name = "DurationOverflowError";
    this.input = input;
    this.ms = ms;
  }
}

/**
 * Converts a `\d+[smhd]` duration string into milliseconds. Throws
 * `DurationParseError` for anything that doesn't match that format, or
 * `DurationOverflowError` if the resulting millisecond value exceeds
 * `MAX_SETTIMEOUT_MS`.
 */
export function parseDuration(text: string): number {
  const match = DURATION_FORMAT_RE.exec(text);
  if (!match) {
    throw new DurationParseError(text);
  }
  const [, digits, unit] = match;
  const value = Number(digits);
  const ms = value * UNIT_MS[unit as DurationUnit];
  if (ms > MAX_SETTIMEOUT_MS) {
    throw new DurationOverflowError(text, ms);
  }
  return ms;
}
