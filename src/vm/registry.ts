// `src/vm/registry.ts` — M8.1: Corb's own session sidecar registry.
//
// Not Gondolin's own session registry (`listSessions`/`findSession`/
// `gcSessions`/`connectToSession`, from `@earendil-works/gondolin`'s
// `session-registry.js`, keyed by `<id>.json` under
// `~/.cache/gondolin/sessions/` — confirmed by reading that file). That
// registry knows nothing about workspaces: its own `SessionInfo` shape is
// just `{ id, pid, socketPath, createdAt, label }`. Corb's sidecar is the
// side-channel that remembers what a session actually mounted and how it was
// configured — `docs/design.md` §7: "dirs, image ref + content hash, audit
// path, pid, started-at" — plus `sessionLabel`, since M8 items after this one
// (`corb ls` etc.) need to display it without re-deriving it.
//
// `id` is deliberately the same value as Gondolin's own `vm.id` — a UUID
// `VM.create()` generates internally via `randomUUID()` (confirmed:
// `node_modules/@earendil-works/gondolin/dist/src/vm/core.js`, `this.id =
// randomUUID()`) — and is also this sidecar's filename stem
// (`sessionSidecarPath`), so a later item can join Gondolin's `listSessions()`
// entries with this module's `listSessionSidecars()` by exact `id` match, no
// separate mapping table required.
//
// `pid` matches what Gondolin's own registry records for the same session:
// `session-registry.js`'s `registerSession` sets `pid: process.pid` — the
// *host* `corb run` process that called `VM.create()`, not the QEMU pid
// (`vm.getHostPid()` is a different, separate value Gondolin exposes but does
// not itself record in its registry). This module follows that same
// convention for its own `pid` field, not because anything here reads
// Gondolin's registry, but so the two sidecars-by-any-other-name agree on
// what "pid" means for a session.
//
// `startedAt` is caller-supplied ISO 8601, not computed internally
// (`Date.now()`/`new Date()`) — matches this codebase's established
// clock-injection discipline, e.g. `src/config/trust.ts`'s
// `recordAcceptance(store, workspaceKey, config, acceptedAt: number)` and
// `src/policy/audit.ts`'s own timestamped-record writer, both of which take
// the "current time" as a parameter rather than reading the clock themselves.
//
// All I/O here is synchronous, mirroring `src/config/trust.ts`'s (and
// `src/config/load.ts`'s) sync file-I/O style — these are small JSON files,
// no need for the async fs API.
//
// Out of scope for this item (left to later M8 items): wiring a sidecar
// write into `src/vm/session.ts`'s `runSession()` (M8.2, which also builds
// the watchdog), any `corb` subcommand (`ls`/`attach`/`kill`/`gc`), and any
// change to Gondolin's own session registry.
import fs from "node:fs";
import path from "node:path";
import { sessionsStateDir } from "../config/paths.ts";

/** One workspace directory a session mounted — see `src/vm/session.ts`'s `WorkspaceDirSpec` (`name`/`hostPath`/`mode`), which this mirrors for the sidecar's own persisted record. */
export interface SessionSidecarDir {
  name: string;
  hostPath: string;
  mode: "ro" | "rw";
}

/** The guest image a session booted from — "image ref + content hash" per `docs/design.md` §7, matching `src/vm/image.ts`'s `ResolvedCorbImage.selector`/`.buildId` fields (not its `arch`/`assetDir`, which are re-derivable and not part of what the sidecar needs to remember). */
export interface SessionSidecarImage {
  selector: string;
  buildId: string | undefined;
}

/**
 * Corb's own session sidecar, persisted as `<id>.json` under
 * `sessionsStateDir()` (default) — see the module comment for what each
 * field means and why. Plain, JSON-serializable data only — no class
 * instances, no methods, matching `src/config/trust.ts`'s
 * `TrustedWorkspaceRecord` precedent for the same reason (round-trips through
 * `JSON.stringify`/`JSON.parse` unchanged).
 */
export interface SessionSidecar {
  /** Matches Gondolin's own `vm.id` and this sidecar's own filename stem — see the module comment. */
  id: string;
  sessionLabel: string;
  dirs: SessionSidecarDir[];
  image: SessionSidecarImage;
  auditPath: string;
  /** The host `corb run` process's own pid — see the module comment for why this is not the QEMU pid. */
  pid: number;
  /** ISO 8601, caller-supplied — see the module comment for why this module never calls `Date.now()`/`new Date()` itself. */
  startedAt: string;
  /**
   * M9.4: present only when this session was booted with `--expose PORT`
   * (`src/commands/run.ts`), wiring Gondolin's ingress reverse proxy
   * (`vm.enableIngress()`/`vm.setIngressRoutes()`, `src/vm/session.ts`).
   * `port` is the guest loopback port that was exposed; `url` is the
   * `IngressAccess.url` a client on the host reaches it through. Omitted
   * entirely (not `undefined`-valued) when ingress was never enabled for
   * this session, matching this interface's own "plain, JSON-serializable
   * data only" discipline — see the module comment.
   */
  exposed?: { port: number; url: string };
}

/**
 * Thrown by `readSessionSidecar`/`listSessionSidecars` when a sidecar file
 * exists but its contents are not a valid `SessionSidecar` — malformed JSON,
 * or JSON that parses but is missing/mistypes a required field. Matches this
 * codebase's `export class XError extends Error { constructor(...) { super(...); this.name = "XError"; } }`
 * convention used throughout `src/vm/session.ts`/`src/vm/image.ts` (e.g.
 * `WorkspaceDirectoryError`, `ImageNotFoundError`). `readSessionSidecar`
 * throws this rather than crashing on a raw `JSON.parse`/`TypeError` — the
 * same "fail clearly, don't crash on garbage" discipline
 * `src/commands/doctor.ts`'s `loadDoctorConfigLayer` already applies to a
 * parallel case (a corrupted `config.toml` layer). A corrupted sidecar must
 * not crash `corb ls`; `listSessionSidecars` below relies on this being a
 * distinguishable, catchable error type to skip just the one bad file.
 */
export class MalformedSessionSidecarError extends Error {
  readonly path: string;

  constructor(sidecarPath: string, reason: string) {
    super(`corb: session sidecar at '${sidecarPath}' is malformed: ${reason}`);
    this.name = "MalformedSessionSidecarError";
    this.path = sidecarPath;
  }
}

/** Path to a session's sidecar file: `<sessionsDir>/<id>.json`. `sessionsDir` defaults to `sessionsStateDir()`. */
export function sessionSidecarPath(id: string, sessionsDir: string = sessionsStateDir()): string {
  return path.join(sessionsDir, `${id}.json`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validates one `dirs[]` entry, following `src/vm/session.ts`'s
 * `parseCorbImageJson`-style manual validation: explicit `typeof` checks per
 * field, no blind casts. `index` is only used to build a precise error
 * message.
 */
function validateDir(value: unknown, index: number, sidecarPath: string): SessionSidecarDir {
  if (!isRecord(value)) {
    throw new MalformedSessionSidecarError(sidecarPath, `'dirs[${index}]' is not an object`);
  }
  if (typeof value.name !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, `'dirs[${index}].name' is missing or not a string`);
  }
  if (typeof value.hostPath !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, `'dirs[${index}].hostPath' is missing or not a string`);
  }
  if (value.mode !== "ro" && value.mode !== "rw") {
    throw new MalformedSessionSidecarError(sidecarPath, `'dirs[${index}].mode' must be 'ro' or 'rw'`);
  }
  return { name: value.name, hostPath: value.hostPath, mode: value.mode };
}

function validateImage(value: unknown, sidecarPath: string): SessionSidecarImage {
  if (!isRecord(value)) {
    throw new MalformedSessionSidecarError(sidecarPath, "'image' is missing or not an object");
  }
  if (typeof value.selector !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, "'image.selector' is missing or not a string");
  }
  if (value.buildId !== undefined && typeof value.buildId !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, "'image.buildId' must be a string when present");
  }
  return { selector: value.selector, buildId: value.buildId };
}

/**
 * Validates the optional M9.4 `exposed` field — present only for a session
 * booted with `--expose PORT` (see `SessionSidecar.exposed`'s own doc
 * comment). `undefined` is a valid, routine input (most sidecars have no
 * `exposed` at all) and returns `undefined` right back; anything else that
 * isn't a well-shaped `{ port: number; url: string }` is malformed, matching
 * `validateImage`'s exact per-field style.
 */
function validateExposed(value: unknown, sidecarPath: string): { port: number; url: string } | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new MalformedSessionSidecarError(sidecarPath, "'exposed' is not an object");
  }
  if (typeof value.port !== "number" || !Number.isInteger(value.port)) {
    throw new MalformedSessionSidecarError(sidecarPath, "'exposed.port' is missing or not an integer");
  }
  if (typeof value.url !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, "'exposed.url' is missing or not a string");
  }
  return { port: value.port, url: value.url };
}

/**
 * Validates a parsed JSON value into a `SessionSidecar`, throwing
 * `MalformedSessionSidecarError` for anything that doesn't fit — every field
 * present and correctly typed, not just "is it an object", matching
 * `parseCorbImageJson`'s (`src/vm/session.ts`) exact style: explicit
 * `typeof`/shape checks per field, no `any`, no blind casts.
 */
function validateSessionSidecar(value: unknown, sidecarPath: string): SessionSidecar {
  if (!isRecord(value)) {
    throw new MalformedSessionSidecarError(sidecarPath, "did not parse to an object");
  }
  if (typeof value.id !== "string" || value.id.length === 0) {
    throw new MalformedSessionSidecarError(sidecarPath, "'id' is missing or not a non-empty string");
  }
  if (typeof value.sessionLabel !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, "'sessionLabel' is missing or not a string");
  }
  if (!Array.isArray(value.dirs)) {
    throw new MalformedSessionSidecarError(sidecarPath, "'dirs' is missing or not an array");
  }
  const dirs = value.dirs.map((dir, index) => validateDir(dir, index, sidecarPath));
  const image = validateImage(value.image, sidecarPath);
  if (typeof value.auditPath !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, "'auditPath' is missing or not a string");
  }
  if (typeof value.pid !== "number" || !Number.isInteger(value.pid)) {
    throw new MalformedSessionSidecarError(sidecarPath, "'pid' is missing or not an integer");
  }
  if (typeof value.startedAt !== "string") {
    throw new MalformedSessionSidecarError(sidecarPath, "'startedAt' is missing or not a string");
  }
  const exposed = validateExposed(value.exposed, sidecarPath);
  return {
    id: value.id,
    sessionLabel: value.sessionLabel,
    dirs,
    image,
    auditPath: value.auditPath,
    pid: value.pid,
    startedAt: value.startedAt,
    ...(exposed !== undefined ? { exposed } : {}),
  };
}

function isEnoent(err: unknown): boolean {
  return err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT";
}

/**
 * Writes `sidecar` to `<sessionsDir>/<sidecar.id>.json` as pretty JSON
 * (2-space indent, trailing newline — matching Gondolin's own
 * `session-registry.js` `registerSession`'s `JSON.stringify(info, null, 2) +
 * "\n"` convention, for consistency with the sibling registry this sits
 * next to conceptually). Creates `sessionsDir` (`mkdir -p`) if it doesn't
 * exist yet — the only one of this module's functions that creates the
 * directory; see `listSessionSidecars`'s own doc comment for why it
 * deliberately does not.
 */
export function writeSessionSidecar(sidecar: SessionSidecar, sessionsDir: string = sessionsStateDir()): void {
  fs.mkdirSync(sessionsDir, { recursive: true });
  fs.writeFileSync(sessionSidecarPath(sidecar.id, sessionsDir), JSON.stringify(sidecar, null, 2) + "\n");
}

/**
 * Reads and validates one session's sidecar. Returns `undefined` if the file
 * doesn't exist (not an error — "no sidecar for this id" is an expected,
 * routine outcome, e.g. a session Gondolin's own registry knows about that
 * predates this module, or one from a version of Corb before M8.1). Throws
 * `MalformedSessionSidecarError` — never a raw `JSON.parse`/`TypeError` — if
 * the file exists but its contents don't validate, so a corrupted sidecar
 * fails clearly rather than crashing whatever called this (`corb ls` etc.).
 */
export function readSessionSidecar(id: string, sessionsDir: string = sessionsStateDir()): SessionSidecar | undefined {
  const sidecarPath = sessionSidecarPath(id, sessionsDir);
  let text: string;
  try {
    text = fs.readFileSync(sidecarPath, "utf8");
  } catch (err) {
    if (isEnoent(err)) {
      return undefined;
    }
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new MalformedSessionSidecarError(sidecarPath, `not valid JSON: ${String(err)}`);
  }
  return validateSessionSidecar(parsed, sidecarPath);
}

/**
 * Reads every `*.json` file in `sessionsDir` as a `SessionSidecar`, silently
 * skipping (not throwing on) any that fail to parse or validate — the same
 * "one corrupted sidecar must not break listing every other one" reasoning
 * `readSessionSidecar` documents for its own `MalformedSessionSidecarError`,
 * just applied across a whole directory instead of one file. Returns `[]` if
 * `sessionsDir` doesn't exist at all, and deliberately does not create it
 * (unlike `writeSessionSidecar`) — a missing directory here just means "no
 * session has ever been started", which not creating an empty one on a
 * read-only listing call keeps true.
 */
export function listSessionSidecars(sessionsDir: string = sessionsStateDir()): SessionSidecar[] {
  let entries: string[];
  try {
    entries = fs.readdirSync(sessionsDir);
  } catch (err) {
    if (isEnoent(err)) {
      return [];
    }
    throw err;
  }

  const sidecars: SessionSidecar[] = [];
  for (const entry of entries) {
    if (!entry.endsWith(".json")) {
      continue;
    }
    const id = entry.slice(0, -".json".length);
    try {
      const sidecar = readSessionSidecar(id, sessionsDir);
      if (sidecar !== undefined) {
        sidecars.push(sidecar);
      }
    } catch (err) {
      if (err instanceof MalformedSessionSidecarError) {
        continue;
      }
      throw err;
    }
  }
  return sidecars;
}

/**
 * Removes a session's sidecar file if present. A no-op, not an error, if it's
 * already gone — mirrors Gondolin's own `unregisterSession`'s `fs.rmSync(...,
 * { force: true })` idempotency (`session-registry.js`), so callers never
 * need to check existence first.
 */
export function removeSessionSidecar(id: string, sessionsDir: string = sessionsStateDir()): void {
  fs.rmSync(sessionSidecarPath(id, sessionsDir), { force: true });
}
