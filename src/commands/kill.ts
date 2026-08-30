// `corb kill <session>` — M8.5: the first command that *acts* on a session
// rather than merely reading one. `corb ls` (M8.4) is strictly read-only and
// says so in its own output; this is its counterpart, and every design choice
// below follows from that one difference.
//
// ## What gets signalled, and why that exact process
//
// `SIGTERM` to the session's owning **host `corb run` process** — the pid both
// registries record for a session (Gondolin's `registerSession` sets `pid:
// process.pid`; Corb's sidecar does the same, deliberately, per
// `src/vm/registry.ts`'s module comment). It is emphatically **not**
// `vm.getHostPid()`, the QEMU process: signalling QEMU directly would kill the
// hypervisor out from under a host process that is still holding a `VM`
// handle, which is the *opposite* of clean teardown.
//
// SIGTERM to the host process lands in the `ShutdownController`
// (`src/vm/shutdown.ts`) that `runSession()` installs before it even creates
// the VM, which runs the full ordered teardown — `clear-watchdog`,
// `restore-tty`, `close-vm`, `remove-sidecar`, `flush-audit` — and then exits
// 143. That ordered path is the entire point of this command: `close-vm` is
// the only reliable termination primitive Corb has (`docs/design.md` §7), and
// `remove-sidecar` is what keeps `corb ls` from growing an orphan row.
//
// ## No `--force`, no SIGKILL — a decision, not an oversight
//
// SIGKILL cannot be caught, so it bypasses `ShutdownController` entirely. What
// it leaves behind is precisely the mess this milestone exists to prevent: the
// QEMU process `close-vm` never got to close keeps running (reparented to
// init, invisible in `corb ls`, holding its memory), and the sidecar
// `remove-sidecar` never got to delete stays on disk as a permanent `orphaned`
// row. That is not a hypothetical: it was observed directly on this machine
// during M8.4's verification — a SIGKILL'd `corb run` left a live
// `qemu-system-x86_64` that had to be found with `pgrep` and killed by hand,
// plus a leftover sidecar.
//
// So there is no `--force` flag and no escalation timer. If SIGTERM does not
// work, a user escalating by hand — with full knowledge that they are about to
// leak a hypervisor process, and with `pgrep -af qemu-system` right there to
// clean up after — is strictly better than Corb offering a one-flag path whose
// predictable outcome is a leaked VM. `parseKillArgs` recognises `--force`/`-f`
// specifically, only so it can explain this rather than emit a bare "unknown
// option".
//
// ## The PID-reuse hazard: never signal something that isn't provably alive
//
// A recorded pid whose process has died may have been recycled by the OS for a
// completely unrelated process. Signalling it would SIGTERM an innocent
// program — by some distance the worst thing this command could plausibly do.
// The guard is: **never signal unless the session is currently, positively
// alive**, using Gondolin's own liveness signal rather than a bare
// `kill(pid, 0)`.
//
// `findSession()` returns a `SessionEntry` carrying `alive` (it delegates to
// `listSessions()` — confirmed by reading `session-registry.js`), and that flag
// is `isPidAlive(pid) && isSocketAlive(socketPath)`. The socket half is what
// makes it meaningfully stronger than a pid check: a recycled pid passes
// `isPidAlive` trivially, but a recycled pid is not going to be listening on
// *this session's* unix socket. `decideKill` refuses to produce a `signal` plan
// for anything else — a not-alive Gondolin entry and a sidecar-only session
// both resolve to a refusal, never to a signal.
//
// **Remaining TOCTOU window, stated honestly:** the `alive` flag is computed
// inside `findSession()`, and the signal is sent some milliseconds later. In
// between, the session could exit and its pid be recycled. That window cannot
// be closed from here — there is no atomic "signal this pid if it is still
// process X" on Linux, and re-checking with a *weaker* test (a bare
// `isPidAlive`) immediately before signalling would add no safety at all, only
// the appearance of it. What is done instead is to keep the window as small as
// possible: `executeKillPlan` does no I/O, no printing and no other registry
// reads between resolution and `sendSignal` — the "sent SIGTERM" line is
// printed *after* the signal, not before, for exactly this reason.
//
// ## Waiting for teardown, rather than firing and returning
//
// After signalling, this waits for the host process to actually exit, bounded
// by `DEFAULT_WAIT_TIMEOUT_MS`. The reason is `corb kill X && corb ls`: a user
// who runs that reasonably expects the session to be gone by the second
// command, and teardown does real work (`vm.close()` takes a moment). Firing
// and returning would make that sequence race, and would report success at a
// point where nothing has actually been torn down yet — the exit code would
// then mean "the signal was delivered", not "the session is gone", which is
// not the question a user is asking.
//
// What is polled is the *host pid* going away, not the registries. That is
// both the cheapest check and the strictly strongest one: the pid disappears
// only after `ShutdownController` has run every step (including
// `remove-sidecar`) and called `process.exit`, so "pid gone" implies "both
// registries already cleaned". Polling `listSessions()` in a loop instead
// would re-run a 500ms-per-dead-socket liveness sweep on every tick for a
// weaker conclusion. The poll is read-only (`kill(pid, 0)`), so pid reuse
// *during* the wait can only make this wait longer and time out — it can never
// cause a signal to be sent. The wait is always bounded and always reports on
// timeout; it never hangs.
//
// ## Structure
//
// The same split `src/commands/ls.ts` and `src/commands/doctor.ts` establish:
// pure decision/formatting functions (`matchSidecarsByQuery`, `decideKill`,
// `parseAmbiguousSessionIds`, `renderKillRefusal`, `parseKillArgs`) plus one
// injectable-dependency executor (`executeKillPlan`), separated from the one
// function that touches real global state (`runKillCommand`, which calls the
// real `findSession()`/`listSessionSidecars()`, the real `process.kill` and
// the real clock). `sendSignal`/`isAlive`/`sleep`/`now` are injectable with
// real defaults, the same seam convention as
// `ShutdownControllerOptions.exit`/`.process` and `ReExecOptions.spawn`/
// `.exit` — a unit test asserts "would have signalled pid N with SIGTERM"
// without ever signalling anything real.
import { parseArgs } from "node:util";
import { findSession, type SessionEntry } from "@earendil-works/gondolin";
import { listSessionSidecars, sessionSidecarPath, type SessionSidecar } from "../vm/registry.ts";

/** What `corb kill` decided to do about the session the user named. Exactly one of these is produced per invocation. */
export type KillPlan =
  /** Resolved to a Gondolin entry that is currently alive — the only plan that ever leads to a signal. */
  | { kind: "signal"; id: string; pid: number; label: string | undefined }
  /** Resolved to a Gondolin entry that is *not* alive: a stale registry row, not a running session. Never signalled — see the module comment's PID-reuse section. */
  | { kind: "not-alive"; id: string; pid: number; label: string | undefined }
  /** Gondolin's registry has nothing, but Corb has a sidecar for it (`corb ls`'s `orphaned` case). Already dead; never signalled. */
  | { kind: "sidecar-only"; id: string; pid: number; label: string }
  /** The query is a prefix of more than one session id, in one registry or the other. */
  | { kind: "ambiguous"; candidates: string[]; rawMessage: string }
  /** Neither registry knows anything matching the query. */
  | { kind: "not-found" };

/**
 * The already-performed lookups `decideKill` reasons over, so the decision
 * itself is pure and unit-testable against fabricated registry contents (the
 * `SessionEntry`/`SessionSidecar` fabrication style `ls.test.ts` established).
 */
export interface KillLookup {
  /** `findSession(query)`'s return value: the matched entry, or `null` for no match. Ignored when `ambiguousMessage` is set. */
  entry: SessionEntry | null;
  /**
   * The message `findSession(query)` **threw** when the query was an ambiguous
   * prefix. The SDK throws (rather than returning) in that case — confirmed by
   * reading `session-registry.js` — and its message usefully names every
   * matching id, so it is captured here rather than discarded.
   */
  ambiguousMessage?: string;
  /** Every Corb sidecar (`listSessionSidecars()`), unfiltered — matching against the query is `decideKill`'s own job, since `readSessionSidecar` needs an exact id and so cannot do prefix matching. */
  sidecars: readonly SessionSidecar[];
}

/**
 * The candidate ids named by the message Gondolin's `findSession` throws for
 * an ambiguous prefix: `` `ambiguous session prefix '<q>' matches N
 * sessions:\n  <id>\n  <id>` ``. Every line after the first, trimmed.
 *
 * Deliberately tolerant: if the SDK ever reshapes that message this returns
 * `[]`, and `renderKillRefusal` falls back to quoting the raw message
 * verbatim. Either way the user sees which sessions matched, which is the
 * property that actually matters — the parse is only about presenting them in
 * Corb's own voice rather than surfacing a raw SDK error, the same reasoning
 * `src/vm/image.ts`'s `ImageNotFoundError` applies to `resolveImageSelector`'s
 * error.
 */
export function parseAmbiguousSessionIds(message: string): string[] {
  return message
    .split("\n")
    .slice(1)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/**
 * Corb sidecars matching `query`, using the same exact-then-unique-prefix rule
 * Gondolin's own `findSession` applies to its registry (including its
 * `query.toLowerCase()` normalisation — session ids are lowercase v4 UUIDs, so
 * this makes `corb kill <ID>` behave identically against either registry).
 * Returns every prefix match, so the caller can tell "one" from "several"
 * rather than this function having to throw the way `findSession` does.
 */
export function matchSidecarsByQuery(sidecars: readonly SessionSidecar[], query: string): SessionSidecar[] {
  const needle = query.toLowerCase();
  const exact = sidecars.find((sidecar) => sidecar.id === needle);
  if (exact !== undefined) {
    return [exact];
  }
  return sidecars.filter((sidecar) => sidecar.id.startsWith(needle));
}

/**
 * Pure resolution of a user's query into exactly one `KillPlan`. Gondolin's
 * registry is authoritative when it has an answer, because it is the only one
 * of the two that carries liveness; Corb's sidecars are consulted only when
 * Gondolin has no match at all, so that an id a user copied out of `corb ls`
 * always produces a message that makes sense rather than a flat "not found".
 *
 * Note what this never does: produce a `signal` plan from a sidecar. A sidecar
 * records a pid but nothing about whether that pid is still the process it was
 * written for, so trusting it would be exactly the PID-reuse bug the module
 * comment describes. A sidecar-only session is reported and left alone.
 *
 * There are two real, brief windows in which a session that is genuinely fine
 * still resolves `sidecar-only`, both observed directly while verifying this
 * item. Neither is a bug here, and neither is this item's to fix — refusing to
 * signal is the correct behaviour in both:
 *
 * - **Startup.** `runSession()` writes the sidecar as soon as `VM.create()`
 *   resolves, but Gondolin registers the session later, from its own lazy
 *   `ensureSessionIpc()`. In between, a booting session shows as `orphaned` to
 *   `corb ls` and resolves `sidecar-only` here. Retrying a moment later
 *   resolves it normally.
 * - **Teardown.** Gondolin's `unregisterSession` runs inside the `close-vm`
 *   shutdown step, while Corb's `remove-sidecar` step runs after it, so a
 *   cleanly-exiting session momentarily has no Gondolin entry but still has a
 *   sidecar. That step ordering is deliberate (`src/vm/session.ts`) and is not
 *   changed by this item.
 */
export function decideKill(query: string, lookup: KillLookup): KillPlan {
  if (lookup.ambiguousMessage !== undefined) {
    return {
      kind: "ambiguous",
      candidates: parseAmbiguousSessionIds(lookup.ambiguousMessage),
      rawMessage: lookup.ambiguousMessage,
    };
  }

  const entry = lookup.entry;
  if (entry !== null) {
    const base = { id: entry.id, pid: entry.pid, label: entry.label };
    return entry.alive ? { kind: "signal", ...base } : { kind: "not-alive", ...base };
  }

  const matches = matchSidecarsByQuery(lookup.sidecars, query);
  if (matches.length > 1) {
    return { kind: "ambiguous", candidates: matches.map((sidecar) => sidecar.id), rawMessage: "" };
  }
  const only = matches[0];
  if (only === undefined) {
    return { kind: "not-found" };
  }
  return { kind: "sidecar-only", id: only.id, pid: only.pid, label: only.sessionLabel };
}

/** Every plan except the one that leads to a signal — i.e. every case `renderKillRefusal` explains. */
export type KillRefusal = Exclude<KillPlan, { kind: "signal" }>;

/** Human-readable session identification for a message: `<id> (<label>)`, or just `<id>` when Gondolin recorded no label (its `label` is optional — see `SessionInfo` in `session-registry.d.ts`). */
function describeSession(id: string, label: string | undefined): string {
  return label !== undefined && label !== "" ? `${id} (${label})` : id;
}

/**
 * The message printed — and the reasoning shown — for every outcome that does
 * not signal anything. Each one says explicitly that nothing was signalled,
 * because "corb kill printed something and exited" must never be ambiguous
 * about whether a signal went out.
 *
 * `sidecarPath` is passed in rather than computed here so this stays pure:
 * `sessionSidecarPath()` defaults to `sessionsStateDir()`, which reads
 * `CORB_STATE_DIR` from the environment. Only the `sidecar-only` case uses it.
 */
export function renderKillRefusal(query: string, plan: KillRefusal, sidecarPath?: string): string {
  switch (plan.kind) {
    case "not-found":
      return (
        `corb kill: no session matches '${query}'.\n` +
        "  Run 'corb ls' to see the sessions that exist and their ids (any unambiguous id prefix works here)."
      );

    case "ambiguous": {
      const listed =
        plan.candidates.length > 0
          ? plan.candidates.map((id) => `  ${id}`).join("\n")
          : plan.rawMessage
              .split("\n")
              .map((line) => `  ${line}`)
              .join("\n");
      return (
        `corb kill: '${query}' is ambiguous — it matches more than one session:\n${listed}\n` +
        "  Nothing was signalled. Re-run with a longer prefix, or with the full id."
      );
    }

    case "not-alive":
      return (
        `corb kill: session ${describeSession(plan.id, plan.label)} is not running.\n` +
        "  Gondolin's registry still has an entry for it, but the session is not alive (its host process, its IPC socket, or both are gone) — " +
        "this is a stale registry entry, not a running session.\n" +
        `  Nothing was signalled: the recorded pid ${plan.pid} may since have been reused by an unrelated process, and signalling it would kill that process instead.`
      );

    case "sidecar-only":
      return (
        `corb kill: session ${describeSession(plan.id, plan.label)} has no live Gondolin session entry.\n` +
        "  Only corb's own sidecar remains — either the session ended without clean teardown (a SIGKILL, a host crash), or it is finishing its teardown right now. " +
        "Either way it is not a session that can be signalled.\n" +
        `  Nothing was signalled: the recorded pid ${plan.pid} may since have been reused by an unrelated process, and signalling it would kill that process instead.` +
        (sidecarPath !== undefined ? `\n  The leftover sidecar is at ${sidecarPath}; 'corb gc' will prune it, until then it can be removed by hand.` : "")
      );
  }
}

/** Sends one signal to one pid. Injectable so a unit test can assert exactly what would have been signalled without signalling anything real — defaults to `process.kill`. */
export type SignalFn = (pid: number, signal: NodeJS.Signals) => void;

/** Read-only liveness probe used only while waiting for teardown. Injectable alongside `SignalFn`, but kept separate from it so a test asserting "nothing was signalled" is unambiguous. */
export type IsAliveFn = (pid: number) => boolean;

/**
 * How long to wait for the signalled host process to finish teardown and exit
 * before giving up and saying so. Generous relative to a real `vm.close()`
 * (about a second in practice), but firmly bounded — see the module comment on
 * why this waits at all, and why it must never hang.
 */
export const DEFAULT_WAIT_TIMEOUT_MS = 15_000;

/** How often to re-probe the host pid while waiting. Cheap (one `kill(pid, 0)`), so this is set for responsiveness rather than to conserve anything. */
export const DEFAULT_POLL_INTERVAL_MS = 200;

export interface KillExecOptions {
  /** Defaults to the real `process.kill`. Override in tests so no real process is ever signalled. */
  sendSignal?: SignalFn;
  /** Defaults to a real `kill(pid, 0)` probe. */
  isAlive?: IsAliveFn;
  /** Defaults to a real `setTimeout`-backed sleep. Override in tests so waiting costs nothing. */
  sleep?: (ms: number) => Promise<void>;
  /** Defaults to `Date.now`. A parameter, never read directly — matching `src/policy/audit.ts`'s `now` and `src/commands/ls.ts`'s `formatAge(startedAt, now)`. */
  now?: () => number;
  /** Defaults to `DEFAULT_WAIT_TIMEOUT_MS`. */
  timeoutMs?: number;
  /** Defaults to `DEFAULT_POLL_INTERVAL_MS`. */
  pollIntervalMs?: number;
  /** Called once, immediately after a successful signal, so a multi-second teardown wait isn't silent. Defaults to `console.log`. */
  report?: (line: string) => void;
  /** Only used to render the `sidecar-only` refusal. Defaults to the real `sessionSidecarPath` (which reads `CORB_STATE_DIR`). */
  sidecarPathFor?: (id: string) => string;
}

/** What one `corb kill` invocation actually did. `exitCode` is the command's own exit status — `0` only on a fully successful kill. */
export interface KillOutcome {
  /** `true` exactly when SIGTERM was actually delivered. The single most important field for a test to assert. */
  signalled: boolean;
  /** Whether the host process was observed to exit within the timeout. Absent when nothing was signalled. */
  exited?: boolean;
  /** The final message to print. */
  message: string;
  /** `0` only when a live session was signalled *and* observed to exit; non-zero for every refusal, every failed signal, and a wait that timed out. */
  exitCode: number;
}

function realSendSignal(pid: number, signal: NodeJS.Signals): void {
  process.kill(pid, signal);
}

/**
 * A real `kill(pid, 0)` liveness probe. `EPERM` counts as alive: the process
 * exists, this uid just may not signal it — reporting it dead would end the
 * wait early and claim a teardown that never happened. Gondolin's own
 * `isPidAlive` collapses every error to "dead"; this is deliberately the
 * stricter reading, since here a false "dead" produces a wrong success report.
 */
function realIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function realSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Polls `isAlive(pid)` until it reports the process gone or `timeoutMs`
 * elapses, whichever comes first. Returns whether the process was observed to
 * exit. Probes once before the first sleep, so an already-exited process
 * returns immediately rather than paying a poll interval.
 *
 * Read-only by construction: this never signals. Pid reuse during the wait can
 * therefore only cause a spurious timeout, never a stray signal.
 */
export async function waitForProcessExit(
  pid: number,
  options: { isAlive: IsAliveFn; sleep: (ms: number) => Promise<void>; now: () => number; timeoutMs: number; pollIntervalMs: number },
): Promise<boolean> {
  const deadline = options.now() + options.timeoutMs;
  for (;;) {
    if (!options.isAlive(pid)) {
      return true;
    }
    if (options.now() >= deadline) {
      return false;
    }
    await options.sleep(options.pollIntervalMs);
  }
}

/**
 * Carries out a `KillPlan`. Every dependency that touches the outside world is
 * injectable (see `KillExecOptions`), so this whole function — including the
 * signal itself and the teardown wait — is unit-testable without signalling
 * any real process or waiting any real time.
 *
 * Note the ordering inside the `signal` case: `sendSignal` is the very first
 * thing that happens, before any printing or path computation, to keep the
 * TOCTOU window between the liveness check and the signal as small as it can
 * be made. See the module comment.
 */
export async function executeKillPlan(query: string, plan: KillPlan, options: KillExecOptions = {}): Promise<KillOutcome> {
  if (plan.kind !== "signal") {
    const sidecarPathFor = options.sidecarPathFor ?? sessionSidecarPath;
    const sidecarPath = plan.kind === "sidecar-only" ? sidecarPathFor(plan.id) : undefined;
    return { signalled: false, message: renderKillRefusal(query, plan, sidecarPath), exitCode: 1 };
  }

  const sendSignal = options.sendSignal ?? realSendSignal;
  const target = describeSession(plan.id, plan.label);

  try {
    sendSignal(plan.pid, "SIGTERM");
  } catch (err) {
    // Almost always `ESRCH`: the session exited on its own in the
    // milliseconds between `findSession()` computing `alive` and this call —
    // the TOCTOU window the module comment describes, landing in its harmless
    // direction. Nothing was signalled, so say so plainly rather than
    // reporting a kill that did not happen.
    const code = (err as NodeJS.ErrnoException).code;
    const detail = code === "ESRCH" ? "it had already exited by the time the signal was sent" : `sending the signal failed (${code ?? String(err)})`;
    return {
      signalled: false,
      message: `corb kill: did not signal session ${target}: ${detail}.\n  Run 'corb ls' to see its current state.`,
      exitCode: 1,
    };
  }

  const report = options.report ?? ((line: string) => console.log(line));
  report(`corb kill: sent SIGTERM to session ${target}, host pid ${plan.pid}; waiting for teardown...`);

  const exited = await waitForProcessExit(plan.pid, {
    isAlive: options.isAlive ?? realIsAlive,
    sleep: options.sleep ?? realSleep,
    now: options.now ?? Date.now,
    timeoutMs: options.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS,
    pollIntervalMs: options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
  });

  if (!exited) {
    const seconds = Math.round((options.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS) / 1000);
    return {
      signalled: true,
      exited: false,
      message:
        `corb kill: SIGTERM was delivered to session ${target} (host pid ${plan.pid}), but it had not exited after ${seconds}s.\n` +
        "  Teardown may still be in progress — check with 'corb ls'. If it never finishes, note that killing it harder (SIGKILL) skips corb's teardown entirely " +
        "and will leave the guest's qemu-system process running and a stale sidecar behind; find the leftover with 'pgrep -af qemu-system' if you go that route.",
      exitCode: 1,
    };
  }

  return {
    signalled: true,
    exited: true,
    message: `corb kill: session ${target} exited; teardown complete.`,
    exitCode: 0,
  };
}

export interface KillCommandArgs {
  /** The session id or unambiguous id prefix the user named. Never empty. */
  session: string;
}

/**
 * `corb kill` takes exactly one positional and no flags. `--force`/`-f` is
 * matched by name purely so the deliberate absence of a SIGKILL path can be
 * explained rather than reported as an unknown option — see the module comment.
 *
 * An empty query is rejected explicitly, and this is a safety check rather
 * than tidiness: `""` is a prefix of *every* id, so `findSession("")` would
 * happily resolve to the user's only running session and kill it.
 */
export function parseKillArgs(argv: string[]): KillCommandArgs {
  if (argv.includes("--force") || argv.includes("-f")) {
    throw new Error(
      "corb kill: there is no --force option, by design.\n" +
        "  corb kill sends SIGTERM so the session's own shutdown can close the VM, remove its sidecar and flush its audit log. " +
        "SIGKILL cannot be caught, so it skips all of that and leaves the guest's qemu-system process running and a stale sidecar behind.\n" +
        "  If a session genuinely will not stop, escalate by hand and clean up after it ('pgrep -af qemu-system').",
    );
  }

  const { positionals } = parseArgs({ args: argv, options: {}, allowPositionals: true, strict: true });

  if (positionals.length === 0) {
    throw new Error("corb kill: missing required argument <session> (a session id, or any unambiguous id prefix — see 'corb ls')");
  }
  if (positionals.length > 1) {
    throw new Error(`corb kill: unexpected argument '${positionals[1]}' (corb kill takes exactly one session id)`);
  }
  const session = positionals[0] ?? "";
  if (session.trim().length === 0) {
    throw new Error("corb kill: <session> must not be empty (an empty query would match every session)");
  }
  return { session };
}

/**
 * The only function here that touches real global state: the real Gondolin
 * session registry, the real sidecar directory, the real `process.kill` and
 * the real clock. Everything it decides is delegated to the pure functions
 * above, and everything it does is delegated to `executeKillPlan` with its
 * real defaults — mirroring `runLsCommand`'s own thin-orchestration shape.
 *
 * `findSession()` **throws** for an ambiguous prefix rather than returning
 * (confirmed in `session-registry.js`), so that case is caught here and turned
 * into a plan. The catch is deliberately unconditional rather than sniffing the
 * message: in practice ambiguity is the only error `findSession` raises for a
 * populated registry, but it reaches `mkdirSync` via `ensureSessionsDir()` and
 * so could also surface an `EACCES`/`ENOSPC`. Treating those as an ambiguity
 * mislabels them — the raw message is still shown verbatim, since
 * `parseAmbiguousSessionIds` yields no candidates for an unrecognised shape and
 * `renderKillRefusal` then quotes `rawMessage` — but it cannot cause harm,
 * which is why it is preferred to matching on SDK message text: every path out
 * of this catch refuses to signal. Failing safe beats failing precisely here.
 *
 * The refusal/failure path sets `process.exitCode` and prints to stderr rather
 * than throwing, following `runDoctorCommand`'s precedent: these are ordinary,
 * expected outcomes a user should read as a sentence, not as a stack trace.
 */
export async function runKillCommand(argv: string[]): Promise<void> {
  // Argument errors are caught and printed as plain sentences here rather
  // than left to `src/cli.ts`'s top-level handler, which prints `err.stack`.
  // `corb ls` lets its own arg errors propagate, and for its one-line
  // messages the stack noise is merely untidy; this command's are multi-line
  // explanations (the `--force` one especially), and burying them under a
  // stack trace defeats the point of writing them. The exit status is the
  // same either way — this only changes what the user reads. `parseKillArgs`
  // still throws, so it stays pure and directly unit-testable.
  let args: KillCommandArgs;
  try {
    args = parseKillArgs(argv);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
    return;
  }

  let entry: SessionEntry | null = null;
  let ambiguousMessage: string | undefined;
  try {
    entry = await findSession(args.session);
  } catch (err) {
    // The SDK's own ambiguity error, whose message names every matching id.
    ambiguousMessage = err instanceof Error ? err.message : String(err);
  }

  // Corb's sidecars are only read when Gondolin had no match at all — the
  // sidecar-only (`orphaned`) case. Skipped otherwise so a normal kill does no
  // extra filesystem work between the liveness check and the signal.
  const sidecars = entry === null && ambiguousMessage === undefined ? listSessionSidecars() : [];
  const plan = decideKill(args.session, {
    entry,
    ...(ambiguousMessage !== undefined ? { ambiguousMessage } : {}),
    sidecars,
  });

  const outcome = await executeKillPlan(args.session, plan);
  if (outcome.exitCode === 0) {
    console.log(outcome.message);
  } else {
    console.error(outcome.message);
    process.exitCode = outcome.exitCode;
  }
}
