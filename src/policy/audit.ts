// `src/policy/audit.ts` — M3.1: the unified audit log's self-contained
// core. Per `docs/design.md` §6, Corb writes every policy decision — HTTP,
// SSH, VFS, gate, plus a fifth `session` channel per the plan's own §7/§8
// wording ("channels http | ssh | vfs | gate | session") — to one JSONL
// file with one schema.
//
// Each `record()` call writes its line to disk immediately (`fs.writeSync`
// on a lazily-opened, append-mode fd), rather than buffering in memory for
// a caller to `flush()` later. An earlier version of this module did the
// opposite — buffer everything, write nothing until `flush()` — on the
// reasoning that batching is cheaper and a caller-controlled flush point is
// simpler to reason about. Both are true, but neither matters as much as
// what buffering costs a *security* log specifically: a `SIGKILL` (or any
// abnormal exit that skips the shutdown sequence — an OOM kill, a crash)
// discarded every event for the entire session, including whatever
// triggered the kill. A guest can also drive that outcome deliberately: a
// tight loop of denied operations grows an unbounded in-memory buffer
// indefinitely, since nothing ever trims or flushes it early, which is a
// guest-triggerable host DoS on top of the log-loss problem. Write-through
// costs one `write(2)` per event, which is the right price for a log whose
// entire purpose is being trustworthy after something has already gone
// wrong. `flush()` is kept as a public method — every existing caller
// already calls it at the point it wants durability guaranteed — but it now
// only closes the fd; every event is already on disk by the time it runs.
//
// `subject`/`reason` are capped at `MAX_SUBJECT_BYTES`/`MAX_REASON_BYTES`
// (`truncateToBytes`) before being stamped: several channels build
// `subject` from guest-controlled input (a VFS path, an HTTP path, an SSH
// repo string — see the call sites in `src/vm/session.ts`, `src/vm/
// egress.ts`, `src/policy/github.ts`, `src/vm/gitssh.ts`), and an unbounded
// string is the same guest-driven growth problem write-through alone
// doesn't solve on its own (a single pathologically long line is still one
// `write(2)`, but an unbounded one).
//
// This module deliberately knows nothing about `src/config/paths.ts`
// (`~/.config`/`~/.local/state`), `ShutdownController`, or a real VM/
// session — those are a later item's job (M3.4) to wire together. Staying
// decoupled from `src/config/` here matches `src/vm/session.ts`'s own
// established discipline of not reaching into the config system directly.
// It also never calls `Date.now()` unconditionally — the clock is
// injectable, same discipline as `src/config/trust.ts`'s
// `recordAcceptance`, so a test controls `ts` deterministically.
import fs from "node:fs";
import path from "node:path";
import { redactKnownSecrets } from "../util/redact.ts";

/** One audit-log line, matching `docs/design.md` §6 exactly plus the `session` channel. */
export interface AuditEvent {
  ts: number;
  channel: "http" | "ssh" | "vfs" | "gate" | "session";
  decision: "allow" | "deny";
  /** Host, repo, path, or op — never a raw URL, header, or query string. Truncated to `MAX_SUBJECT_BYTES` before being recorded. */
  subject: string;
  /** Truncated to `MAX_REASON_BYTES` before being recorded. */
  reason?: string;
  sessionId: string;
}

/** Byte cap applied to `subject` before an event is written — some channels build it from guest-controlled input (a VFS path, an HTTP path). Matches `src/policy/sentinel.ts`'s `MAX_PATH_BYTES` precedent for "how long is a legitimate path allowed to be". */
export const MAX_SUBJECT_BYTES = 4 * 1024;

/** Byte cap applied to `reason` before an event is written — same guest-controlled-input reasoning as `MAX_SUBJECT_BYTES`. */
export const MAX_REASON_BYTES = 4 * 1024;

const TRUNCATION_MARKER = "...[truncated]";

/** Truncates `value` to at most `maxBytes` UTF-8 bytes, appending `TRUNCATION_MARKER` when it does. Cutting on a byte boundary can split a multi-byte character; `Buffer#toString` replaces the resulting partial sequence with U+FFFD rather than producing invalid UTF-8, an acceptable cosmetic cost on an already-oversized string. */
function truncateToBytes(value: string, maxBytes: number): string {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) {
    return value;
  }
  const markerBytes = Buffer.byteLength(TRUNCATION_MARKER, "utf8");
  const budget = Math.max(0, maxBytes - markerBytes);
  const truncated = Buffer.from(value, "utf8").subarray(0, budget).toString("utf8");
  return truncated + TRUNCATION_MARKER;
}

export interface AuditWriterOptions {
  /** Where `flush()` appends JSONL lines. A plain path — this module has no opinion about where it lives. */
  path: string;
  /**
   * Known-sensitive string values scrubbed from `subject`/`reason` before an
   * event is buffered. Defense in depth on top of the primary mechanism
   * (channels only ever constructing safe `subject`/`reason` strings in the
   * first place) — see `src/util/redact.ts`. Defaults to none, i.e. no
   * redaction pass beyond whatever the caller already constructed safely.
   */
  redactSecrets?: readonly string[];
  /** Defaults to `Date.now`. Overridden in tests so `record()`'s `ts` is deterministic. */
  now?: () => number;
}

/**
 * A write-through JSONL writer for the unified audit log. `record()` writes
 * its line to disk before returning — see the module comment for why this
 * replaced an earlier buffer-and-`flush()` design. No
 * `process.on("exit", ...)` or similar hook lives here; a caller (M3.4)
 * still owns the session lifecycle, it just no longer needs to remember to
 * flush for durability — only to release the fd via `flush()` when done.
 */
export interface AuditWriter {
  /** Stamps `ts` via the injected clock, applies the redaction scrub (if configured) and the `MAX_SUBJECT_BYTES`/`MAX_REASON_BYTES` truncation, and writes the event to disk synchronously before returning. */
  record(event: Omit<AuditEvent, "ts">): void;
  /**
   * Adds more known-sensitive values to the redaction list `record()`
   * consults, on top of whatever `redactSecrets` was passed at construction
   * time. Exists because the real secret values (`buildSecretBindings()`,
   * `src/vm/egress.ts`) aren't known yet at the point `createAuditWriter()`
   * is called (`src/commands/run.ts`) — a caller that learns them later
   * (`buildEgressConfig()`) registers them here instead. Only affects events
   * recorded *after* this call; does not retroactively scrub anything
   * already written to disk.
   */
  addRedactedSecrets(values: readonly string[]): void;
  /**
   * Closes the underlying file descriptor, if one has been opened. Every
   * event `record()` was given has already been written to disk by the
   * time this runs — this is a resource-release step, not a durability
   * one. Safe to call when nothing has ever been recorded (no fd was ever
   * opened) and safe to call more than once (idempotent), matching every
   * existing call site's usage (`src/vm/session.ts`'s `flush-audit`
   * shutdown step, `src/vm/attach.ts`).
   */
  flush(): void;
}

/** Creates a new `AuditWriter` targeting `options.path`. Opens no file descriptor and touches no disk until the first `record()` call. */
export function createAuditWriter(options: AuditWriterOptions): AuditWriter {
  const filePath = options.path;
  const redactSecrets = new Set(options.redactSecrets ?? []);
  const now = options.now ?? Date.now;
  let fd: number | undefined;

  function ensureOpen(): number {
    if (fd === undefined) {
      // `recursive: true` is a no-op if the directory already exists, so an
      // already-existing, more-permissive directory is left as-is here —
      // this only sets `0o700` on a directory this call itself creates.
      fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
      fd = fs.openSync(filePath, "a", 0o600);
      // `openSync`'s mode argument only applies when it creates the file —
      // it does not retroactively tighten an existing, more permissive log
      // (e.g. one written by a Corb build from before this fix, or created
      // under a looser umask). `chmodSync` makes the 0600 invariant hold
      // regardless of the file's prior state.
      fs.chmodSync(filePath, 0o600);
    }
    return fd;
  }

  function record(event: Omit<AuditEvent, "ts">): void {
    const secrets = [...redactSecrets];
    const subject = truncateToBytes(redactKnownSecrets(event.subject, secrets), MAX_SUBJECT_BYTES);
    const reason =
      event.reason === undefined ? undefined : truncateToBytes(redactKnownSecrets(event.reason, secrets), MAX_REASON_BYTES);
    const stamped: AuditEvent = {
      ts: now(),
      channel: event.channel,
      decision: event.decision,
      subject,
      ...(reason === undefined ? {} : { reason }),
      sessionId: event.sessionId,
    };
    fs.writeSync(ensureOpen(), `${JSON.stringify(stamped)}\n`);
  }

  function addRedactedSecrets(values: readonly string[]): void {
    for (const value of values) {
      redactSecrets.add(value);
    }
  }

  function flush(): void {
    if (fd !== undefined) {
      fs.closeSync(fd);
      fd = undefined;
    }
  }

  return { record, addRedactedSecrets, flush };
}
