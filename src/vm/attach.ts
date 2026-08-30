// `src/vm/attach.ts` — M8.7: `corb attach <session>`, the raw-protocol
// client. Everything the M0.4 spike (`spike/m0-4-exec-concurrency/
// attach-client.mjs`, `docs/spike-results.md` "M0.4 — R2") already proved
// empirically against a real booted `corb:0.1.0` image is treated here as
// settled fact, not re-derived: `exec` is genuinely concurrent (a second
// exec, including an interactive `pty: true` one, runs alongside a session's
// own long-lived exec with zero cross-talk), and `connectToSession()` is a
// raw JSON-control-message + binary-output-frame client with no built-in
// stdio wiring of its own — this module hand-rolls that wiring, the same way
// the spike does.
//
// ## This can never rejoin Pi's own TUI, and that is not a compromise
//
// The control protocol (`node_modules/@earendil-works/gondolin/dist/src/
// sandbox/control-protocol.d.ts`) has no "list execs" and no "join exec N"
// message. `SessionIpcServer` gives every external client connection its own
// internal exec-id space (`session-registry.js`'s `handleConnection`), and
// addressing another client's exec id is refused with `{"type":"error",
// "code":"unknown_id",...}` — confirmed by the spike's own "ATTACH CHECK 4".
// So `corb attach` cannot rejoin the stream Pi's TUI is writing to; it can
// only start a brand-new exec (a shell) inside the already-running guest,
// alongside Pi. That is what this command *is*, not a fallback for
// something it was supposed to do instead — every user-facing string this
// module produces says so plainly, per the M8.7 brief's explicit
// instruction not to let any of them imply otherwise.
//
// ## What the attached shell does not have: the original session's secrets
//
// The secret placeholder environment variables `createHttpHooks()` bound
// for the original `corb run` process exist only in that process's own
// memory — a different OS process from whatever runs `corb attach`, started
// later. There is nowhere on disk `corb attach` could read them back from,
// and that is correct: Corb's security model is built on secrets never
// existing outside the one process that bound them. A `git`/`curl`/etc. run
// from this attached shell therefore makes real, credential-less requests —
// no placeholder substitution happens here. This is a deliberate, permanent
// limitation, not a gap left to close later; see `buildAttachEnv` and
// `ATTACH_BANNER` below, both of which say so to whoever actually attaches.
//
// ## Why frames are decoded by hand instead of importing `decodeOutputFrame`
//
// `control-protocol.d.ts` exports `encodeOutputFrame`/`decodeOutputFrame`,
// but neither reaches this module: `@earendil-works/gondolin`'s
// `package.json` `"exports"` map only lists `"."` (→ `dist/src/index.js`)
// and `"./package.json"` — no subpath export for `dist/src/sandbox/
// control-protocol.js`. A deep import of that path throws
// `ERR_PACKAGE_PATH_NOT_EXPORTED` at run time (confirmed empirically against
// the installed package), and `index.d.ts` itself does not re-export either
// function. So `decodeAttachFrame` below hand-decodes the same `u8 tag, u32
// BE id, data` layout the spike already decodes by hand, for the same
// reason: there is no supported import path to the real one.
//
// Likewise `ExecCommandMessage`/`ServerMessage`/`ClientMessage` (also
// `control-protocol.d.ts`-only) are not importable by name. `AttachExecMessage`
// below duplicates `ExecCommandMessage`'s shape rather than importing it —
// the same "the real type isn't reachable, so the shape is re-declared
// locally" move `src/vm/session.ts`'s `parseCorbImageJson`/`CorbImageJson`
// already makes for `/etc/corb/image.json`'s own shape, just applied to an
// SDK-internal type instead of an on-disk file format. Everything sent over
// the wire (`stdin`, `pty_resize`) that this module doesn't need to unit-test
// the exact shape of is passed as a plain object literal instead, which
// TypeScript checks structurally against `connectToSession()`'s own
// `send(message: ClientMessage)` parameter type without ever needing to
// import `ClientMessage` by name.
//
// ## Promise hygiene: never reject, so nothing can go unhandled
//
// The single most important trap this module is built around: `docs/design.md`'s
// own history already hit "closing a VM rejects a live exec's promise, and
// an un-awaited rejection can take down the host process." That trap is
// specific to `vm.exec()`'s `ExecProcess` promises (the SDK's own
// abstraction, used by `src/vm/session.ts`'s `runSession()`) — this module
// never touches a `VM` or an `ExecProcess` at all, so it cannot inherit that
// exact failure mode. But it recreates the same *shape* of risk by hand
// (a promise per exec, resolved by a later network event that may never
// arrive if the socket dies first), so it is built to be immune to it by
// construction: every exec's internal bookkeeping promise (`startExec`
// below) only ever **resolves**, never rejects — a closed connection, a
// timeout, or an `error` control message all resolve the same promise with
// a `{ kind: "error", ... }` outcome instead. There is therefore no
// rejection anywhere in this module's own promise graph for something to
// fail to observe, closed-VM-mid-attach included.
//
// ## Structure
//
// Same split every other M8 command module uses: pure resolution
// (`resolveAttachTarget`, mirroring `src/commands/kill.ts`'s `decideKill`
// almost exactly — the `KillLookup` shape is reused verbatim, not
// re-invented) and rendering (`renderAttachRefusal`) functions, pure
// message-building helpers (`buildIdentityExecMessage`,
// `buildAttachShellExecMessage`, `buildAttachEnv`), and one function that
// touches the real socket and real streams (`runAttachSession`) with every
// host-touching dependency injectable — `connect`, the streams, `acquireTty`
// — the same `ProcessLike`/`ExitFn`-style seam convention
// `shutdown.ts`/`scope.ts`/`kill.ts` already establish.
import { connectToSession, type IpcClientCallbacks } from "@earendil-works/gondolin";
import { acquire, canRequestPty } from "./tty.ts";
import { parseCorbImageJson, WORKSPACE_PUBLIC_ROOT, type CorbImageJson } from "./session.ts";
import { matchSidecarsByQuery, parseAmbiguousSessionIds, type KillLookup } from "../commands/kill.ts";
import type { AuditWriter } from "../policy/audit.ts";

// Re-exported so a caller (`src/commands/attach.ts`) can build a `KillLookup`
// without importing it from `kill.ts` directly — matches this module's own
// re-export-rather-than-duplicate stance on `matchSidecarsByQuery`/
// `parseAmbiguousSessionIds` below.
export type { KillLookup } from "../commands/kill.ts";
export { matchSidecarsByQuery, parseAmbiguousSessionIds };

/**
 * What `corb attach` decided to do about the session the user named.
 * Mirrors `src/commands/kill.ts`'s `KillPlan` exactly, except the one
 * live-and-actionable case is `connect` (carrying the socket path to dial)
 * rather than `signal` — everything else (`not-alive`, `sidecar-only`,
 * `ambiguous`, `not-found`) is identical in meaning and in when it applies.
 * A `connect` plan is only ever produced from a Gondolin entry that is
 * `alive` — a not-alive entry has no live socket to connect to, exactly
 * `decideKill`'s own reasoning for refusing to signal a stale entry.
 */
export type AttachPlan =
  | { kind: "connect"; id: string; socketPath: string; label: string | undefined }
  | { kind: "not-alive"; id: string; pid: number; label: string | undefined }
  | { kind: "sidecar-only"; id: string; pid: number; label: string }
  | { kind: "ambiguous"; candidates: string[]; rawMessage: string }
  | { kind: "not-found" };

/**
 * Pure resolution of a user's query into exactly one `AttachPlan` —
 * structurally identical to `decideKill` (`src/commands/kill.ts`), reusing
 * the same `KillLookup` input and the same `matchSidecarsByQuery`/
 * `parseAmbiguousSessionIds` helpers rather than re-implementing either.
 * See `KillLookup`'s own doc comment for what each field means; see
 * `decideKill`'s own doc comment for why a sidecar is never trusted to
 * produce the live-and-actionable case (there, `signal`; here, `connect`) —
 * the identical PID-reuse reasoning applies to `alive`, not just to `pid`:
 * a sidecar carries neither, so it can never tell this apart from a dead
 * session either.
 */
export function resolveAttachTarget(query: string, lookup: KillLookup): AttachPlan {
  if (lookup.ambiguousMessage !== undefined) {
    return {
      kind: "ambiguous",
      candidates: parseAmbiguousSessionIds(lookup.ambiguousMessage),
      rawMessage: lookup.ambiguousMessage,
    };
  }

  const entry = lookup.entry;
  if (entry !== null) {
    if (entry.alive) {
      return { kind: "connect", id: entry.id, socketPath: entry.socketPath, label: entry.label };
    }
    return { kind: "not-alive", id: entry.id, pid: entry.pid, label: entry.label };
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

/** Every plan except the one that leads to a connection — i.e. every case `renderAttachRefusal` explains. */
export type AttachRefusal = Exclude<AttachPlan, { kind: "connect" }>;

/** Human-readable session identification for a message: `<id> (<label>)`, or just `<id>` when Gondolin recorded no label. Mirrors `kill.ts`'s own `describeSession`. */
function describeSession(id: string, label: string | undefined): string {
  return label !== undefined && label !== "" ? `${id} (${label})` : id;
}

/**
 * The message printed — and the reasoning shown — for every outcome that
 * does not connect anything. Mirrors `renderKillRefusal`'s voice and level
 * of detail almost line for line, with "signalled" replaced by "attached"
 * throughout (this command's own irreversible-action word) and the
 * `sidecar-only`/`not-alive` explanations reworded around "no live socket to
 * attach to" rather than "nothing to safely signal" — same underlying
 * reasoning, different verb.
 */
export function renderAttachRefusal(query: string, plan: AttachRefusal, sidecarPath?: string): string {
  switch (plan.kind) {
    case "not-found":
      return (
        `corb attach: no session matches '${query}'.\n` +
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
        `corb attach: '${query}' is ambiguous — it matches more than one session:\n${listed}\n` +
        "  Nothing was attached. Re-run with a longer prefix, or with the full id."
      );
    }

    case "not-alive":
      return (
        `corb attach: session ${describeSession(plan.id, plan.label)} is not running.\n` +
        "  Gondolin's registry still has an entry for it, but the session is not alive (its host process, its IPC socket, or both are gone) — " +
        "this is a stale registry entry, not a running session with a socket to attach to.\n" +
        "  Nothing was attached."
      );

    case "sidecar-only":
      return (
        `corb attach: session ${describeSession(plan.id, plan.label)} has no live Gondolin session entry.\n` +
        "  Only corb's own sidecar remains. That means the session ended without clean teardown (a SIGKILL, a host crash), or is starting up or finishing teardown right now, " +
        "or is still running but unreachable because its IPC socket was never created (run 'corb doctor' — an over-long session socket path fails silently). " +
        "In none of those cases is there a live socket to attach to.\n" +
        "  Nothing was attached." +
        (sidecarPath !== undefined
          ? `\n  The leftover sidecar is at ${sidecarPath}. If the session has really ended, 'corb gc' prunes it. ` +
            "If its host process is in fact still alive, gc deliberately keeps it and it must not be deleted by hand."
          : "")
      );
  }
}

// Mirrors `src/vm/session.ts`'s own module-private `GUEST_PATH` exactly.
// Duplicated rather than imported: that module deliberately keeps it
// unexported, and array-form `exec` runs no login shell (`docs/gondolin-notes.md`
// §3), so this exact `PATH` must be set explicitly for every exec issued
// here too, the same way `session.ts` sets it for its own `dropcap`/`pi`
// exec. Keep this in sync with `session.ts` if that value ever changes.
const GUEST_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/**
 * Mirrors `@earendil-works/gondolin`'s `ExecCommandMessage`
 * (`sandbox/control-protocol.d.ts`) — not itself part of the package's
 * public export surface (see the module comment), so its shape is
 * duplicated here rather than imported. Structurally identical to what
 * `connectToSession()`'s returned `send()` accepts, so passing one of these
 * straight to `send()` type-checks without any cast.
 */
export interface AttachExecMessage {
  type: "exec";
  id: number;
  cmd: string;
  argv?: string[];
  env?: string[];
  cwd?: string;
  stdin?: boolean;
  pty?: boolean;
}

/** Fixed, single-use ids for the two execs one `corb attach` connection ever issues — no id reuse, no need to mint anything fresh. */
export const IDENTITY_EXEC_ID = 1;
export const SHELL_EXEC_ID = 2;

/**
 * The one-shot `/bin/cat /etc/corb/image.json` exec used to learn the
 * guest's uid/gid/dropcap path — the same file `src/vm/session.ts`'s
 * `readGuestIdentity` reads via `vm.exec()`, just issued over the raw
 * protocol here instead, since this module has no `VM` object to call
 * `.exec()` on.
 */
export function buildIdentityExecMessage(id: number): AttachExecMessage {
  return { type: "exec", id, cmd: "/bin/cat", argv: ["/etc/corb/image.json"], env: [`PATH=${GUEST_PATH}`] };
}

/**
 * The guest environment for the attached shell: `HOME`/`USER`/`PATH` from
 * the guest's own identity (matching `session.ts`'s `buildGuestEnv`
 * convention exactly), plus `TERM` passed through from the local host's
 * `TERM` when set (same convention, same reasoning: array-form `exec` runs
 * no login shell, so nothing is inherited from `/etc/profile`).
 *
 * Deliberately absent: every secret placeholder `buildGuestEnv` also sets.
 * See the module comment's "What the attached shell does not have" section
 * — those exist only in the original `corb run` process's own memory, in a
 * different OS process, and there is nowhere this module could read them
 * back from even if it tried to.
 */
export function buildAttachEnv(identity: CorbImageJson, hostEnv: NodeJS.ProcessEnv): string[] {
  const env = [`HOME=${identity.paths.home}`, `USER=${identity.user}`, `PATH=${GUEST_PATH}`];
  if (hostEnv.TERM !== undefined) {
    env.push(`TERM=${hostEnv.TERM}`);
  }
  return env;
}

/**
 * The interactive shell exec: `dropcap <uid> <gid> /bin/sh`, `cwd: /work`,
 * `stdin: true`, `pty: true` — the exact shape the M0.4 spike proved
 * interactive-capable under dropcap (`ATTACH CHECK 3`), with `/bin/sh`
 * specifically (not `/bin/bash` — only `/bin/sh` was actually exercised
 * under dropcap+pty in the spike). `cwd` is `WORKSPACE_PUBLIC_ROOT`
 * (`/work`, `session.ts`) rather than any one workspace directory: it is a
 * real rootfs directory every mounted workspace dir sits under, so it is a
 * sensible default regardless of how many/which dirs this session mounted.
 */
export function buildAttachShellExecMessage(id: number, identity: CorbImageJson, hostEnv: NodeJS.ProcessEnv): AttachExecMessage {
  return {
    type: "exec",
    id,
    cmd: identity.paths.dropcapPath,
    argv: [String(identity.uid), String(identity.gid), "/bin/sh"],
    cwd: WORKSPACE_PUBLIC_ROOT,
    env: buildAttachEnv(identity, hostEnv),
    stdin: true,
    pty: true,
  };
}

/** Decode a binary output frame payload: `u8 tag, u32 BE id, data` — see the module comment for why this is hand-decoded rather than imported. */
function decodeAttachFrame(frame: Buffer): { id: number; stream: "stdout" | "stderr"; data: Buffer } {
  const tag = frame.readUInt8(0);
  const id = frame.readUInt32BE(1);
  return { id, stream: tag === 2 ? "stderr" : "stdout", data: frame.subarray(5) };
}

/** How long `runAttachSession` waits for the guest to answer the one-shot identity read before giving up — generous for a `cat` of a tiny file, but bounded, so an unresponsive session cannot hang this command forever. */
export const DEFAULT_IDENTITY_TIMEOUT_MS = 15_000;

/**
 * Exit code `runAttachSession` reports when the connection ends (or was
 * never usable) for a reason other than the shell's own exit — a
 * `queue_full`/other exec-start error, or the session ending mid-attach.
 * Distinct from any real shell exit code (0-255 by POSIX convention) so a
 * caller can always tell "the shell exited with this code" apart from "the
 * shell never really ran" by exit code alone, matching `runSession()`'s own
 * precedent of reserving a specific, documented code for a non-exit
 * termination (124 for the watchdog, `src/vm/session.ts`).
 */
export const ATTACH_CONNECTION_ENDED_EXIT_CODE = 125;

/** Printed once, right before the interactive shell starts, so nobody attaches without first reading it. See the module comment. */
export function buildAttachBanner(plan: Extract<AttachPlan, { kind: "connect" }>, identity: CorbImageJson): string {
  return (
    `corb attach: opening a NEW shell (uid ${identity.uid}) inside session ${describeSession(plan.id, plan.label)}. ` +
    "This is a separate shell alongside Pi's own — Gondolin's protocol has no way to rejoin another client's exec, so this can never reattach to Pi's own TUI. " +
    "Secret placeholders configured for this session are not available here (they exist only in the original 'corb run' process's own memory): " +
    "git/curl/etc. run from this shell make real, credential-less requests."
  );
}

type ExecOutcome = { kind: "exit"; exitCode: number; signal?: number | undefined } | { kind: "error"; code: string; message: string };

interface PendingExec {
  resolve: (outcome: ExecOutcome) => void;
  onBinary?: ((stream: "stdout" | "stderr", data: Buffer) => void) | undefined;
}

/** `connectToSession` itself, injectable so a test never opens a real socket. Defaults to the real SDK function. */
export type ConnectFn = typeof connectToSession;

/**
 * What this module needs from stdin: the raw-mode surface `tty.ts`'s
 * `acquire`/`canRequestPty` already require (`isTTY`/`isRaw`/`setRawMode`),
 * plus the ability to receive raw data chunks (forwarded as base64 `stdin`
 * control messages) and to stop listening on cleanup. A structural
 * subtype of `tty.ts`'s own `RawModeCapableStream`, not declared as
 * `extends` it, purely so a plain object literal satisfies this in tests
 * without also having to satisfy that interface's exact optional-property
 * shape.
 */
export interface AttachStdin {
  readonly isTTY?: boolean;
  readonly isRaw?: boolean;
  setRawMode?(mode: boolean): unknown;
  on(event: "data", listener: (chunk: Buffer) => void): unknown;
  off(event: "data", listener: (chunk: Buffer) => void): unknown;
}

/**
 * What this module needs from stdout: `tty.ts`'s own TTY-detection surface
 * (`isTTY`), a `write` that accepts the `Buffer` chunks binary output frames
 * decode to (wider than `tty.ts`'s own `WritableTtyStream.write(chunk:
 * string)`, which this module's own writes don't need — output bytes are
 * never re-encoded as text here), plus real terminal geometry (for
 * `pty_resize`) and resize notifications kept live for the whole session
 * (unlike the spike, which only ever sent one fixed resize).
 */
export interface AttachStdout {
  readonly isTTY?: boolean;
  readonly rows?: number;
  readonly columns?: number;
  write(chunk: Buffer | string): unknown;
  on(event: "resize", listener: () => void): unknown;
  off(event: "resize", listener: () => void): unknown;
}

export interface AttachSessionOptions {
  /** Defaults to the real `connectToSession`. Override in tests so no real socket is ever opened. */
  connect?: ConnectFn;
  stdin?: AttachStdin;
  stdout?: AttachStdout;
  stderr?: { write(chunk: Buffer | string): unknown };
  /** Read for `TERM` — see `buildAttachEnv`. Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** Defaults to the real `acquire` (`./tty.ts`). Override in tests so no real raw-mode call happens. */
  acquireTty?: typeof acquire;
  /** Defaults to `DEFAULT_IDENTITY_TIMEOUT_MS`. */
  identityTimeoutMs?: number;
  /**
   * Where this attach's one audit event is recorded, when the caller has one
   * available (i.e. found a Corb sidecar for this session — see
   * `src/commands/attach.ts`). `undefined` skips the audit record entirely
   * rather than failing the attach over it: a session Corb didn't start (a
   * bare SDK session, `corb ls`'s "gondolin-only" case) has no audit path to
   * write to, and that is not a reason to refuse a legitimate connect.
   */
  audit?: AuditWriter;
  /** Called once with `buildAttachBanner`'s text, right before the interactive shell starts. Defaults to `console.error`. Injectable so a test can capture it instead of writing to real stderr. */
  report?: (line: string) => void;
}

/** What one `runAttachSession` call actually did. `exitCode` is the command's own exit status — see `ATTACH_CONNECTION_ENDED_EXIT_CODE`'s doc comment for what a non-shell-exit code means. */
export interface AttachOutcome {
  message: string;
  exitCode: number;
}

function raceTimeout<T>(promise: Promise<T>, ms: number): Promise<T | "timeout"> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve("timeout"), ms);
    // Only ever resolves (see the module comment's "Promise hygiene"
    // section) — `promise` itself is `startExec`'s own never-rejecting
    // promise, so there is nothing here to `.catch()`.
    void promise.then((value) => {
      clearTimeout(timer);
      resolve(value);
    });
  });
}

/**
 * Connects to a running session's raw IPC socket, reads its guest identity,
 * opens one `dropcap`-privileged interactive shell inside it, and wires the
 * local terminal to it for the shell's whole lifetime. Resolves cleanly in
 * every case — a refused connect, an unresponsive guest, the connection
 * dying mid-session, or the shell's own normal exit — never throws and never
 * leaves an unhandled rejection behind (see the module comment).
 *
 * Only ever called with a `connect`-kind `AttachPlan` — `src/commands/
 * attach.ts` handles every refusal case via `renderAttachRefusal` before
 * this is reached.
 */
export async function runAttachSession(
  plan: Extract<AttachPlan, { kind: "connect" }>,
  options: AttachSessionOptions = {},
): Promise<AttachOutcome> {
  const stdin = options.stdin ?? (process.stdin as unknown as AttachStdin);
  const stdout = options.stdout ?? (process.stdout as unknown as AttachStdout);
  const stderr = options.stderr ?? process.stderr;
  const hostEnv = options.env ?? process.env;
  const connect = options.connect ?? connectToSession;
  const doAcquire: typeof acquire = options.acquireTty ?? acquire;
  const identityTimeoutMs = options.identityTimeoutMs ?? DEFAULT_IDENTITY_TIMEOUT_MS;
  const report = options.report ?? ((line: string) => console.error(line));

  // Refuse outright rather than silently falling back to a non-interactive
  // exec — `corb attach` only ever offers an interactive shell, and a piped
  // or redirected stdin/stdout could never drive one. Mirrors `session.ts`'s
  // own `canRequestPty` guard, but here it is a hard refusal rather than a
  // "skip the pty" fallback: `runSession()` can still usefully run Pi
  // without a pty, but a shell with no pty and no stdin loop is not what
  // this command exists to offer.
  if (!canRequestPty(stdin, stdout)) {
    return {
      message:
        "corb attach: stdin and stdout must both be a real terminal. " +
        "corb attach opens an interactive shell, which cannot run over piped or redirected input/output.",
      exitCode: 1,
    };
  }

  const pending = new Map<number, PendingExec>();
  let closedReason: string | undefined;

  const callbacks: IpcClientCallbacks = {
    onJson(message) {
      if (message.type === "exec_response") {
        const rec = pending.get(message.id);
        pending.delete(message.id);
        rec?.resolve({ kind: "exit", exitCode: message.exit_code, signal: message.signal });
        return;
      }
      if (message.type === "error" && message.id !== undefined) {
        const rec = pending.get(message.id);
        pending.delete(message.id);
        rec?.resolve({ kind: "error", code: message.code, message: message.message });
      }
      // A connection-level error (no `id`) or a `status`/`snapshot_response`
      // message: nothing keyed here to react to. A connection-level error is
      // still followed by the socket closing, which `onClose` below handles.
    },
    onBinary(frame) {
      const { id, stream, data } = decodeAttachFrame(frame);
      pending.get(id)?.onBinary?.(stream, data);
    },
    onClose(err) {
      // Idempotent-safe to call more than once (`conn.close()` in the
      // `finally` below also triggers this): the second call finds `pending`
      // already empty and touches nothing.
      closedReason = err ? err.message : "the connection closed";
      for (const rec of pending.values()) {
        rec.resolve({ kind: "error", code: "connection_closed", message: closedReason });
      }
      pending.clear();
    },
  };

  const conn = connect(plan.socketPath, callbacks);

  /**
   * Starts one exec and returns a promise for its outcome. Never rejects —
   * see the module comment's "Promise hygiene" section — resolving instead
   * with `{ kind: "error", code: "connection_closed", ... }` for a
   * connection that is already dead by the time this is called (closing the
   * race between `onClose` firing and this being invoked in the caller's
   * own favor, rather than registering a pending entry that can now never
   * resolve).
   */
  function startExec(id: number, message: AttachExecMessage, onBinary?: PendingExec["onBinary"]): Promise<ExecOutcome> {
    return new Promise((resolve) => {
      if (closedReason !== undefined) {
        resolve({ kind: "error", code: "connection_closed", message: closedReason });
        return;
      }
      pending.set(id, { resolve, onBinary });
      conn.send(message);
    });
  }

  try {
    const identityChunks: Buffer[] = [];
    const identityResult = await raceTimeout(
      startExec(IDENTITY_EXEC_ID, buildIdentityExecMessage(IDENTITY_EXEC_ID), (stream, data) => {
        if (stream === "stdout") {
          identityChunks.push(data);
        }
      }),
      identityTimeoutMs,
    );

    if (identityResult === "timeout") {
      return {
        message: `corb attach: timed out after ${identityTimeoutMs}ms waiting for the guest to answer (reading /etc/corb/image.json). The session may be unresponsive.`,
        exitCode: 1,
      };
    }
    if (identityResult.kind === "error") {
      // Mirrors the shell-stage error handling below: only a genuine
      // connection close gets the distinct `ATTACH_CONNECTION_ENDED_EXIT_CODE`
      // — any other exec-start error (`queue_full`, etc.) is a plain failure
      // to report, not a "the session ended" outcome.
      return identityResult.code === "connection_closed"
        ? {
            message: `corb attach: the session ended before it could be attached to (${identityResult.message}).`,
            exitCode: ATTACH_CONNECTION_ENDED_EXIT_CODE,
          }
        : {
            message: `corb attach: could not start a shell in this session (${identityResult.code}): ${identityResult.message}`,
            exitCode: 1,
          };
    }
    if (identityResult.exitCode !== 0) {
      return {
        message: `corb attach: could not read /etc/corb/image.json from the guest (exit ${identityResult.exitCode}).`,
        exitCode: 1,
      };
    }

    let identity: CorbImageJson;
    try {
      identity = parseCorbImageJson(Buffer.concat(identityChunks).toString("utf8"));
    } catch (err) {
      return { message: `corb attach: ${err instanceof Error ? err.message : String(err)}`, exitCode: 1 };
    }

    if (options.audit !== undefined) {
      options.audit.record({
        channel: "session",
        decision: "allow",
        subject: plan.label ?? plan.id,
        reason: "attach",
        sessionId: plan.id,
      });
      options.audit.flush();
    }

    report(buildAttachBanner(plan, identity));

    const ttyHandle = doAcquire(stdin, stdout);
    try {
      const sendResize = (): void => {
        conn.send({ type: "pty_resize", id: SHELL_EXEC_ID, rows: stdout.rows ?? 24, cols: stdout.columns ?? 80 });
      };
      const onResize = (): void => sendResize();
      const onStdinData = (chunk: Buffer): void => {
        conn.send({ type: "stdin", id: SHELL_EXEC_ID, data: chunk.toString("base64") });
      };

      const shellPromise = startExec(SHELL_EXEC_ID, buildAttachShellExecMessage(SHELL_EXEC_ID, identity, hostEnv), (stream, data) => {
        (stream === "stdout" ? stdout : stderr).write(data);
      });

      // Live geometry from the very start, then forwarded for the whole
      // life of the session — the spike only ever sent one fixed resize;
      // production needs the real thing (`process.stdout.on("resize", ...)`
      // equivalent) for a genuinely usable interactive shell.
      sendResize();
      stdout.on("resize", onResize);
      stdin.on("data", onStdinData);

      try {
        const outcome = await shellPromise;
        if (outcome.kind === "exit") {
          return { message: `corb attach: shell exited (${outcome.exitCode}); session ${describeSession(plan.id, plan.label)} is still running.`, exitCode: outcome.exitCode };
        }
        if (outcome.code === "connection_closed") {
          return { message: `corb attach: the session ended while attached (${outcome.message}).`, exitCode: ATTACH_CONNECTION_ENDED_EXIT_CODE };
        }
        return { message: `corb attach: the shell could not be started (${outcome.code}): ${outcome.message}`, exitCode: 1 };
      } finally {
        stdin.off("data", onStdinData);
        stdout.off("resize", onResize);
      }
    } finally {
      ttyHandle.restore();
    }
  } finally {
    conn.close();
  }
}
