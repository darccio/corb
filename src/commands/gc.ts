// `corb gc [--older-than DURATION]` — M8.6: the first command in Corb that
// **deletes** anything. `corb ls` (M8.4) only reads; `corb kill` (M8.5)
// signals but removes no file. This one removes files, and every design
// choice below follows from that.
//
// Per `docs/design.md` §7 it does two things, in this order: it calls
// Gondolin's own `gcSessions()` (which collects the SDK's stale `<id>.json`
// metadata and orphaned `<id>.sock` files from its sessions directory), then
// it prunes Corb's own orphaned sidecars (`src/vm/registry.ts`, M8.1).
//
// ## The organising idea: two deliberately asymmetric guards
//
// **`corb kill` requires positive proof of *life* before it acts. `corb gc`
// requires positive proof of *death* before it deletes.** Both fail safe by
// refusing to act under uncertainty, and they are asymmetric *on purpose* —
// they are protecting against opposite mistakes:
//
// - `kill` signals, so its nightmare is signalling a pid that has been
//   recycled by an unrelated process. It therefore demands the *strongest*
//   available liveness evidence: Gondolin's `alive`, which is
//   `isPidAlive(pid) && isSocketAlive(socketPath)`.
// - `gc` deletes, so its nightmare is deleting the record of a session that is
//   still running. It therefore demands the *strongest* available deadness
//   evidence, and — crucially — treats *any* sign of life as disqualifying,
//   including the weak one (`kill(pid, 0)` alone) that `kill` deliberately
//   refuses to act on.
//
// A future reader "simplifying" one of these two guards to look like the other
// would break one of the two commands. They are not the same test and must not
// be unified.
//
// ## The mandatory guard: never prune a sidecar whose recorded pid is alive
//
// `decideSidecarGc` checks `isAlive(sidecar.pid)` **first and
// unconditionally**, before any age arithmetic, and a live pid always wins.
//
// A bare pid check is conservative in exactly the right direction here. Pid
// reuse can make a genuinely-prunable sidecar look alive — the cost of that is
// one stale file left on disk, which is harmless and which the next `corb gc`
// retries. The opposite mistake deletes the sidecar of a *running* session,
// which permanently loses the only record of what that session mounted, which
// image it booted and where its audit log went, and makes it unmanageable
// through `corb ls`/`corb kill`/`corb attach`. Prefer leaving garbage over
// losing a live session's record.
//
// Note what is deliberately **not** used as the deadness test: Gondolin's own
// `alive` flag, or its registry's presence/absence. Both report a healthy
// session as dead in two already-observed situations, which is precisely why
// the pid guard is load-bearing rather than belt-and-braces:
//
// 1. **The startup window.** `runSession()` writes Corb's sidecar as soon as
//    `VM.create()` resolves, but Gondolin only registers the session later,
//    from its own lazy `ensureSessionIpc()`. A booting session was directly
//    observed presenting as `orphaned` to `corb ls` for roughly 12 seconds.
//    Its host pid is alive throughout — which is exactly what the pid guard
//    catches.
// 2. **The socket-overflow trap** (`src/vm/sockpath.ts`). When Gondolin's
//    sessions directory pushes a session's socket path past 108 characters the
//    bind fails silently and the `.sock` is never created, so `isSocketAlive()`
//    is false and `listSessions()` reports `alive: false` **forever** for a
//    session that is genuinely running. This has a sharp edge specific to this
//    command: `gcSessions()` treats a missing socket as stale, so it will
//    happily delete that live session's Gondolin metadata, leaving it
//    sidecar-only immediately afterwards. The pid guard — and only the pid
//    guard — is what then saves its sidecar. Note this is not even specific to
//    running `corb gc`: Gondolin's own `ensureSessionIpc()` calls `gcSessions()`
//    itself before registering a session (`vm/core.js`), so merely starting
//    *another* session already strips a live-but-socketless session's Gondolin
//    metadata. Verified directly, both ways.
//
// There is a third, briefer window the same guard covers: **teardown.**
// Gondolin's `unregisterSession` runs inside the `close-vm` shutdown step
// while Corb's `remove-sidecar` step runs after it, so a cleanly-exiting
// session momentarily has no Gondolin entry but still has a sidecar (see
// `decideKill`'s own doc comment). Its pid is still alive in that moment. That
// step ordering is deliberate and is not changed by this item.
//
// ## Sequencing: why running `gcSessions()` first is safe
//
// `gcSessions()` runs before sidecars are evaluated, and that ordering
// genuinely changes what the sidecar half sees: a session whose Gondolin entry
// was stale a moment ago has no Gondolin entry at all afterwards, so its
// sidecar now reads as sidecar-only/`orphaned`. That is fine — but *only*
// because the sidecar decision consults `isAlive(pid)` and nothing else.
// Nothing in `decideSidecarGc` reads Gondolin's registry, directly or
// indirectly, so `gcSessions()` cannot influence its verdict. This is by
// construction, not by luck: if a future change ever makes the prune decision
// depend on Gondolin's registry contents, this ordering becomes a live bug and
// the socket-overflow case above becomes a data-loss bug.
//
// ## Structure
//
// The same split `src/commands/ls.ts` and `src/commands/kill.ts` establish:
// pure decision and rendering functions (`parseGcArgs`, `decideSidecarGc`,
// `renderGcReport`) plus an injectable-dependency executor
// (`executeSidecarGc`), separated from the one function that touches real
// global state (`runGcCommand`, which calls the real `gcSessions()`, the real
// sidecar directory, the real `process.kill` probe and the real clock). The
// liveness probe, the clock and the removal function are all injectable with
// real defaults, so a unit test can assert both "would have pruned exactly
// these" and — the most important assertion in `gc.test.ts` — "did NOT call
// remove for the live one", without touching the filesystem.
//
// `formatAge`/`idColumnWidth` are imported from `src/commands/ls.ts` rather
// than re-implemented: they are pure, already exported, and already this
// codebase's answer to "render a session listing". A second age formatter that
// could drift from the one `corb ls` prints would be strictly worse.
import { parseArgs } from "node:util";
import { gcSessions } from "@earendil-works/gondolin";
import { listSessionSidecars, removeSessionSidecar, type SessionSidecar } from "../vm/registry.ts";
import { parseDuration } from "../util/duration.ts";
import { formatAge, idColumnWidth } from "./ls.ts";

/** Read-only liveness probe. Injectable so a unit test can decide what is alive without any real process existing — defaults to a real `kill(pid, 0)`. Mirrors `src/commands/kill.ts`'s own `IsAliveFn` seam. */
export type IsAliveFn = (pid: number) => boolean;

/** Removes one sidecar file. Injectable so a unit test can assert exactly which ids would have been deleted — and, more importantly, which would not — without deleting anything. Defaults to `removeSessionSidecar` (`src/vm/registry.ts`). */
export type RemoveSidecarFn = (id: string) => void;

/**
 * Why one sidecar was or was not pruned. Exactly one applies per sidecar, and
 * only `"dead"` prunes.
 *
 * - `"dead"` — the recorded host pid is gone, and the age filter (if any) is
 *   satisfied. The only reason that deletes anything.
 * - `"alive"` — the recorded host pid is still alive. **The mandatory guard**;
 *   see the module comment. Checked first, so it always wins over age.
 * - `"too-recent"` — provably dead, but younger than `--older-than`.
 * - `"unknown-age"` — provably dead, but its `startedAt` is unparseable, so it
 *   cannot be *shown* to satisfy `--older-than`. Only reachable when
 *   `--older-than` was given; with no age filter there is nothing to prove.
 */
export type GcSidecarReason = "dead" | "alive" | "too-recent" | "unknown-age";

/** One sidecar's verdict. `prune` is `true` exactly when `reason === "dead"`; both are carried so callers can branch on whichever reads better at the call site. */
export interface GcSidecarDecision {
  sidecar: SessionSidecar;
  prune: boolean;
  reason: GcSidecarReason;
  /** Milliseconds since `startedAt`, clamped at 0 for a future timestamp (host clock skew); `undefined` when `startedAt` is unparseable. */
  ageMs: number | undefined;
}

/**
 * The whole decision, pure: which sidecars qualify for pruning, given the
 * sidecars, a liveness probe, a clock reading, and a minimum age.
 *
 * The pid guard is evaluated **first and unconditionally** — a live pid is
 * disqualifying no matter how old the sidecar is. Read the module comment
 * before changing that ordering or weakening that test.
 *
 * `now` is a number rather than a clock function, matching
 * `src/commands/ls.ts`'s `formatAge(startedAt, now)` and `src/policy/audit.ts`'s
 * `now` — one reading is taken by the caller and applied consistently to every
 * sidecar in the batch.
 */
export function decideSidecarGc(
  sidecars: readonly SessionSidecar[],
  options: { isAlive: IsAliveFn; now: number; minAgeMs: number },
): GcSidecarDecision[] {
  return sidecars.map((sidecar) => {
    const started = Date.parse(sidecar.startedAt);
    const ageMs = Number.isNaN(started) ? undefined : Math.max(0, options.now - started);

    // THE guard. Nothing below this line can reach a live session's sidecar.
    if (options.isAlive(sidecar.pid)) {
      return { sidecar, prune: false, reason: "alive", ageMs };
    }

    if (options.minAgeMs > 0) {
      if (ageMs === undefined) {
        // Provably dead but not provably old: refuse, because the user asked
        // for an age bound and this sidecar cannot be shown to satisfy it.
        return { sidecar, prune: false, reason: "unknown-age", ageMs };
      }
      if (ageMs < options.minAgeMs) {
        return { sidecar, prune: false, reason: "too-recent", ageMs };
      }
    }

    return { sidecar, prune: true, reason: "dead", ageMs };
  });
}

/** One sidecar whose removal was attempted and failed — a real failure (a permissions problem, a read-only filesystem), not a refusal. `removeSessionSidecar` is already idempotent for an already-gone file, so this is never "it wasn't there". */
export interface GcPruneFailure {
  id: string;
  error: string;
}

/** What `executeSidecarGc` actually did. */
export interface GcPruneResult {
  /** Ids whose sidecar file was removed — or, under `--dry-run`, would have been. */
  prunedIds: string[];
  failures: GcPruneFailure[];
}

/**
 * Carries out the prune decisions. The removal function is injected (default:
 * the real `removeSessionSidecar`), which is what lets `gc.test.ts` assert
 * that remove was called for exactly the dead sidecars and *not* called for a
 * live one, without a filesystem anywhere in the test.
 *
 * `dryRun` short-circuits before any removal at all rather than swapping in a
 * no-op function, so there is no configuration in which a dry run could reach
 * a real `rmSync`.
 *
 * One failing removal does not abort the batch: the remaining prunable
 * sidecars are still attempted and the failure is reported alongside them,
 * matching `listSessionSidecars`'s own "one bad file must not break the rest"
 * discipline.
 */
export function executeSidecarGc(
  decisions: readonly GcSidecarDecision[],
  options: { removeSidecar?: RemoveSidecarFn; dryRun?: boolean } = {},
): GcPruneResult {
  const remove = options.removeSidecar ?? removeSessionSidecar;
  const result: GcPruneResult = { prunedIds: [], failures: [] };

  for (const decision of decisions) {
    if (!decision.prune) {
      continue;
    }
    if (options.dryRun === true) {
      result.prunedIds.push(decision.sidecar.id);
      continue;
    }
    try {
      remove(decision.sidecar.id);
      result.prunedIds.push(decision.sidecar.id);
    } catch (err) {
      result.failures.push({ id: decision.sidecar.id, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return result;
}

/** Everything one `corb gc` run produced, gathered so rendering stays pure and the whole outcome is assertable in one place. */
export interface GcReport {
  /**
   * How many session ids Gondolin's own `gcSessions()` collected (its return
   * value: the size of its stale-id set, covering both stale `<id>.json`
   * metadata and orphaned `<id>.sock` files — confirmed by reading
   * `session-registry.js`). `undefined` when it was not run at all: see
   * `--dry-run`, which cannot preview it.
   */
  gondolinCollected: number | undefined;
  /** `gcSessions()`'s own failure message, when it threw. Its work is independent of the sidecar half, so a failure here is reported but does not prevent sidecar pruning. */
  gondolinError?: string;
  decisions: readonly GcSidecarDecision[];
  prune: GcPruneResult;
  dryRun: boolean;
  /** The raw `--older-than` string the user passed, for messaging. `undefined` means no age filter. */
  olderThan: string | undefined;
  /** The clock reading every age in `decisions` was measured against — reused here so the rendered ages match the ones the decisions were made from. */
  now: number;
}

function describeSidecar(sidecar: SessionSidecar, idWidth: number, now: number): string {
  const label = sidecar.sessionLabel !== "" ? ` (${sidecar.sessionLabel})` : "";
  return `  ${sidecar.id.slice(0, idWidth)}${label}  age ${formatAge(sidecar.startedAt, now)}`;
}

/** The explanation attached to each listed sidecar — every kept one says, in its own line, exactly why it was left alone. A cleanup command that silently skips things is indistinguishable from a broken one. */
function reasonText(decision: GcSidecarDecision, olderThan: string | undefined): string {
  const pid = decision.sidecar.pid;
  switch (decision.reason) {
    case "dead":
      return `host pid ${pid} is gone`;
    case "alive":
      return `host pid ${pid} is still alive — this session is running, starting up, or shutting down`;
    case "too-recent":
      return `host pid ${pid} is gone, but it started inside the --older-than ${olderThan ?? ""} window`;
    case "unknown-age":
      return `host pid ${pid} is gone, but its recorded startedAt is unparseable, so it cannot be shown to be older than --older-than ${olderThan ?? ""}`;
  }
}

/** Oldest first (the most obviously collectable garbage at the top), with an unparseable age sorting last and `id` as a deterministic tie-break so repeated runs print the same order. */
function byAgeDescending(a: GcSidecarDecision, b: GcSidecarDecision): number {
  const left = a.ageMs ?? -1;
  const right = b.ageMs ?? -1;
  return right - left || a.sidecar.id.localeCompare(b.sidecar.id);
}

/**
 * The human-readable report. Says all four things a user of a destructive
 * command needs: what Gondolin itself collected, what was pruned and why it
 * qualified, what was **skipped** and for what reason, and — when nothing
 * happened — that nothing happening was the correct outcome rather than a
 * failure.
 */
export function renderGcReport(report: GcReport): string {
  const lines: string[] = [];
  const verb = report.dryRun ? "would prune" : "pruned";
  const keptVerb = report.dryRun ? "would keep" : "kept";

  if (report.gondolinError !== undefined) {
    lines.push(`corb gc: gondolin's own gcSessions() failed: ${report.gondolinError}`);
    lines.push("  Its registry was left as it was; corb's own sidecars were still evaluated below.");
  } else if (report.gondolinCollected === undefined) {
    lines.push(
      "corb gc: --dry-run: gondolin's own gcSessions() was NOT run. It deletes unconditionally and has no preview mode, " +
        "so nothing in gondolin's registry was inspected or touched.",
    );
  } else {
    const n = report.gondolinCollected;
    lines.push(`corb gc: gondolin collected ${n} stale registry ${n === 1 ? "entry" : "entries"}.`);
  }

  const total = report.decisions.length;
  const pruned = report.decisions.filter((d) => d.prune);
  const kept = report.decisions.filter((d) => !d.prune);
  const filter =
    report.olderThan !== undefined
      ? `--older-than ${report.olderThan}: only sidecars started more than ${report.olderThan} ago qualify`
      : "no --older-than filter: every sidecar whose host pid is gone qualifies";

  lines.push(
    `corb gc: examined ${total} corb sidecar${total === 1 ? "" : "s"} (${filter}); ` +
      `${verb} ${pruned.length}, ${keptVerb} ${kept.length}.`,
  );

  const idWidth = idColumnWidth(report.decisions.map((d) => d.sidecar.id));

  if (pruned.length > 0) {
    lines.push(`corb gc: ${verb}:`);
    for (const decision of [...pruned].sort(byAgeDescending)) {
      lines.push(`${describeSidecar(decision.sidecar, idWidth, report.now)}  ${reasonText(decision, report.olderThan)}`);
    }
  }

  if (kept.length > 0) {
    lines.push(`corb gc: ${keptVerb}:`);
    for (const decision of [...kept].sort(byAgeDescending)) {
      lines.push(`${describeSidecar(decision.sidecar, idWidth, report.now)}  ${reasonText(decision, report.olderThan)}`);
    }
  }

  if (kept.some((d) => d.reason === "alive")) {
    lines.push(
      "corb gc: a sidecar whose recorded host pid is still alive is never pruned. Deleting one would lose a running session's " +
        "record of what it mounted and where its audit log went, and make it unmanageable through 'corb ls'/'corb kill'.",
    );
  }

  for (const failure of report.prune.failures) {
    lines.push(`corb gc: failed to remove the sidecar for ${failure.id}: ${failure.error}`);
  }

  // The "nothing at all happened, and nothing was even a candidate" case.
  // Stated explicitly because a cleanup command that prints two zeroes and
  // exits is otherwise indistinguishable from one that is broken. Deliberately
  // not printed when something *was* examined and kept — those runs already
  // say, line by line, exactly what was skipped and why.
  if (report.gondolinError === undefined && report.prune.failures.length === 0 && (report.gondolinCollected ?? 0) === 0 && total === 0) {
    lines.push("corb gc: nothing to collect: no stale gondolin entries and no corb sidecars. That is a clean state, not a failure.");
  }

  return lines.join("\n");
}

export interface GcCommandArgs {
  /** The raw `--older-than` string, kept for messaging. `undefined` when the flag was not given. */
  olderThan: string | undefined;
  /** `olderThan` in milliseconds; `0` (no age filter) when the flag was not given — see `DEFAULT_MIN_AGE_MS`. */
  minAgeMs: number;
  dryRun: boolean;
}

/**
 * The default minimum age: **none**. With no `--older-than`, every sidecar
 * whose recorded host pid is gone is pruned, however recently it died.
 *
 * A grace period was considered and rejected. The pid guard already covers
 * every window in which a healthy session looks dead (startup, teardown, and
 * the socket-overflow trap — see the module comment), so a default grace
 * period would be defence in depth, not the actual protection. Against that,
 * it has a real cost: `corb gc` exists to clean up, and a user who has just
 * seen an `orphaned` row in `corb ls` and runs `corb gc` would be told
 * "examined 1, pruned 0" and reasonably conclude the command is broken. The
 * predictable next step is deleting the sidecar by hand — which has no pid
 * guard at all, and is therefore *less* safe than what a defaulted-off grace
 * period was trying to buy.
 *
 * Note also what an age filter can and cannot rule out. A dead recorded pid
 * means the session is definitively over: the pid *is* the host `corb run`
 * process that owned the VM, so it cannot be dead while the session lives.
 * Waiting longer does not make that conclusion any more true. `--older-than`
 * is therefore offered as an explicit, opt-in policy ("only collect things
 * that have been dead a while") rather than imposed as a safety default it
 * would not actually be providing.
 */
export const DEFAULT_MIN_AGE_MS = 0;

/**
 * `corb gc [--older-than DURATION] [--dry-run|-n]`, no positionals.
 *
 * `--older-than` is parsed with `parseDuration` (`src/util/duration.ts`, the
 * `\d+[smhd]` format `vm.max-session` already uses) rather than a second
 * parser, so `1h` means the same thing everywhere in Corb. Its
 * `DurationParseError` is re-thrown with the command's own prefix so a
 * malformed value names the flag it came from.
 */
export function parseGcArgs(argv: string[]): GcCommandArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      "older-than": { type: "string" },
      "dry-run": { type: "boolean", short: "n" },
    },
    // Accepted by the parser and rejected here (rather than banned via
    // `allowPositionals: false`) purely so the error names the command and the
    // offending argument — `parseLsArgs`'s own precedent.
    allowPositionals: true,
    strict: true,
  });

  if (positionals.length > 0) {
    throw new Error(`corb gc: unexpected argument '${positionals[0]}' (corb gc takes no positional arguments)`);
  }

  const olderThan = values["older-than"];
  let minAgeMs = DEFAULT_MIN_AGE_MS;
  if (olderThan !== undefined) {
    try {
      minAgeMs = parseDuration(olderThan);
    } catch {
      throw new Error(`corb gc: invalid --older-than '${olderThan}' (expected a duration like '30s', '5m', '4h', or '1d')`);
    }
  }

  return { olderThan, minAgeMs, dryRun: values["dry-run"] ?? false };
}

/**
 * A real `kill(pid, 0)` liveness probe. `EPERM` counts as **alive**: the
 * process exists, this uid just may not signal it. That is the safe reading
 * for this command specifically — reporting such a pid dead would delete a
 * live session's sidecar, the exact outcome the guard exists to prevent.
 * Gondolin's own `isPidAlive` collapses every error to "dead"; this is
 * deliberately stricter, for the same reason `src/commands/kill.ts`'s
 * `realIsAlive` is.
 */
function realIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * The only function here that touches real global state: Gondolin's real
 * session registry, the real sidecar directory, the real `process.kill` probe
 * and the real clock. Everything it decides is delegated to `decideSidecarGc`
 * and everything it does to `executeSidecarGc`, mirroring `runLsCommand`'s and
 * `runKillCommand`'s own thin-orchestration shape.
 *
 * `gcSessions()` runs first, per `docs/design.md` §7 — see the module
 * comment's sequencing section for why that is safe, and for what would make
 * it unsafe. It is wrapped in a `try` because its work is entirely independent
 * of the sidecar half: a failure there (an `EACCES` reaching `mkdirSync` via
 * its own `ensureSessionsDir()`) is worth reporting, but is no reason to leave
 * Corb's own orphaned sidecars uncollected.
 *
 * Under `--dry-run`, `gcSessions()` is not called at all. It has no preview
 * mode and deletes unconditionally, so calling it would make `--dry-run` a
 * lie about half of what this command does. The sidecar half previews exactly
 * faithfully regardless, because its verdict does not depend on Gondolin's
 * registry at all.
 */
export async function runGcCommand(argv: string[]): Promise<void> {
  // Argument errors are printed as plain sentences here rather than left to
  // `src/cli.ts`'s top-level handler (which prints `err.stack`) — the same
  // choice `runKillCommand` documents, for the same reason: these are ordinary
  // user-facing messages, not crashes. `parseGcArgs` still throws, so it stays
  // pure and directly unit-testable.
  let args: GcCommandArgs;
  try {
    args = parseGcArgs(argv);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
    return;
  }

  let gondolinCollected: number | undefined;
  let gondolinError: string | undefined;
  if (!args.dryRun) {
    try {
      gondolinCollected = await gcSessions();
    } catch (err) {
      gondolinError = err instanceof Error ? err.message : String(err);
    }
  }

  // One clock reading for the whole run, applied to both the decisions and
  // their rendering, so the age a sidecar was judged on is exactly the age
  // printed next to it.
  const now = Date.now();
  const decisions = decideSidecarGc(listSessionSidecars(), {
    isAlive: realIsAlive,
    now,
    minAgeMs: args.minAgeMs,
  });
  const prune = executeSidecarGc(decisions, { dryRun: args.dryRun });

  const report: GcReport = {
    gondolinCollected,
    ...(gondolinError !== undefined ? { gondolinError } : {}),
    decisions,
    prune,
    dryRun: args.dryRun,
    olderThan: args.olderThan,
    now,
  };

  const message = renderGcReport(report);
  // Exit 0 for any successful run, explicitly including "nothing to do" —
  // non-zero is reserved for real failures (a removal that could not be
  // performed, or `gcSessions()` itself throwing), never for "there was no
  // garbage".
  if (gondolinError === undefined && prune.failures.length === 0) {
    console.log(message);
    return;
  }
  console.error(message);
  process.exitCode = 1;
}
