// `src/policy/audit.ts` — M3.1: the unified audit log's self-contained
// core. Per `docs/design.md` §6, Corb writes every policy decision — HTTP,
// SSH, VFS, gate, plus a fifth `session` channel per the plan's own §7/§8
// wording ("channels http | ssh | vfs | gate | session") — to one JSONL
// file with one schema, buffered in memory and flushed at a controlled
// point rather than written line-by-line as events happen.
//
// This module deliberately knows nothing about `src/config/paths.ts`
// (`~/.config`/`~/.local/state`), `ShutdownController`, or a real VM/
// session — those are a later item's job (M3.4) to wire together. Staying
// decoupled from `src/config/` here matches `src/vm/session.ts`'s own
// established discipline of not reaching into the config system directly;
// staying decoupled from `ShutdownController` keeps this an inert
// buffer+writer with no side effects until `flush()` is explicitly called.
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
  /** Host, repo, path, or op — never a raw URL, header, or query string. */
  subject: string;
  reason?: string;
  sessionId: string;
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
 * A buffered JSONL writer for the unified audit log. `record()` only
 * appends to an in-memory buffer; nothing reaches disk until `flush()` is
 * called explicitly. No `process.on("exit", ...)` or similar hook lives
 * here — a caller (M3.4) owns deciding when to flush.
 */
export interface AuditWriter {
  /** Stamps `ts` via the injected clock, applies the redaction scrub (if configured), and buffers the event. Does not touch disk. */
  record(event: Omit<AuditEvent, "ts">): void;
  /**
   * Adds more known-sensitive values to the redaction list `record()`
   * consults, on top of whatever `redactSecrets` was passed at construction
   * time. Exists because the real secret values (`buildSecretBindings()`,
   * `src/vm/egress.ts`) aren't known yet at the point `createAuditWriter()`
   * is called (`src/commands/run.ts`) — a caller that learns them later
   * (`buildEgressConfig()`) registers them here instead. Only affects events
   * recorded *after* this call; does not retroactively scrub anything
   * already buffered.
   */
  addRedactedSecrets(values: readonly string[]): void;
  /**
   * Appends every buffered event as one JSON line each to the configured
   * path (creating its parent directory if needed), then clears the
   * buffer. Always appends — never truncates or clobbers existing content,
   * since this may be a long-lived log spanning many Corb invocations.
   */
  flush(): void;
}

/** Creates a new, empty `AuditWriter` targeting `options.path`. */
export function createAuditWriter(options: AuditWriterOptions): AuditWriter {
  const filePath = options.path;
  const redactSecrets = new Set(options.redactSecrets ?? []);
  const now = options.now ?? Date.now;
  const buffer: AuditEvent[] = [];

  function record(event: Omit<AuditEvent, "ts">): void {
    const secrets = [...redactSecrets];
    const subject = redactKnownSecrets(event.subject, secrets);
    const reason = event.reason === undefined ? undefined : redactKnownSecrets(event.reason, secrets);
    const stamped: AuditEvent = {
      ts: now(),
      channel: event.channel,
      decision: event.decision,
      subject,
      ...(reason === undefined ? {} : { reason }),
      sessionId: event.sessionId,
    };
    buffer.push(stamped);
  }

  function addRedactedSecrets(values: readonly string[]): void {
    for (const value of values) {
      redactSecrets.add(value);
    }
  }

  function flush(): void {
    if (buffer.length === 0) {
      return;
    }
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const lines = buffer.map((event) => JSON.stringify(event)).join("\n") + "\n";
    fs.appendFileSync(filePath, lines);
    buffer.length = 0;
  }

  return { record, addRedactedSecrets, flush };
}
