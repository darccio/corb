// `corb ls` — M8.4: the first command that reads Corb's session sidecars
// (`src/vm/registry.ts`, M8.1) back. Read-only inspection of what sessions
// exist right now, without booting or touching anything — the same posture
// `src/commands/explain.ts` takes for a workspace's config.
//
// This is the sidecar/registry join `docs/design.md` §7 ("Cleanup and session
// sidecars") describes: Gondolin's own session registry (`listSessions()`,
// from `@earendil-works/gondolin`'s `session-registry.js`) knows a session's
// `{ id, pid, socketPath, createdAt, label, alive }` and nothing about
// workspaces; Corb's sidecar knows the mounted dirs, the image ref and its
// content hash, and the audit path, and nothing about liveness. Neither is
// sufficient alone. `id` is the join key — deliberately so, per
// `src/vm/registry.ts`'s own module comment: the sidecar's `id` *is*
// Gondolin's `vm.id`, and is also both files' filename stem, so this needs no
// mapping table.
//
// ## Three join cases, all three real
//
// - **both** — a normal `corb run` session. Full detail.
// - **gondolin-only** — a Gondolin VM this Corb did not start (a bare SDK
//   user, a Corb predating M8.1, or a sidecar someone deleted by hand). Still
//   listed: it is a real VM the user may care about, just with the
//   workspace-specific columns left empty rather than fabricated.
// - **sidecar-only** — an orphan. The session ended without clean teardown (a
//   `SIGKILL`, a host crash), so `runSession()`'s `remove-sidecar` shutdown
//   step never ran. Surfaced and marked `orphaned`, because it is exactly what
//   `corb gc` (M8.6) will exist to prune and a user needs to see it before
//   then. **Nothing here deletes anything** — `corb ls` is strictly read-only;
//   pruning is M8.6's job, not this command's.
//
// ## Structure
//
// The pure join (`joinSessions`) and the pure renderers (`renderLsText`,
// `renderLsJson`, `formatAge`, `idColumnWidth`) are separated from the one
// function that touches real global state (`runLsCommand`, which calls the
// real `listSessions()`/`listSessionSidecars()` and reads the real clock),
// mirroring `src/commands/doctor.ts`'s established split exactly: pure
// `classify*`/`build*` functions unit-tested against fabricated input, one
// thin orchestration function that isn't. `formatAge` takes `now` as a
// parameter rather than calling `Date.now()` itself, matching this codebase's
// clock-injection discipline (`src/policy/audit.ts`'s `now` option,
// `src/config/trust.ts`'s `recordAcceptance(…, acceptedAt)`,
// `src/vm/registry.ts`'s caller-supplied `startedAt`).
//
// Table alignment is hand-rolled (a max-width pass, then `padEnd`) rather
// than pulled from a formatting dependency — `package.json`'s runtime
// dependency list is deliberately two entries long and a column-padding loop
// does not earn a third.
//
// On error this deliberately does not add a second error-formatting layer:
// `src/cli.ts`'s top-level `.catch()` already prints `err.stack ??
// err.message` for anything that escapes `main()`. In practice very little
// can escape — `listSessionSidecars` silently skips malformed sidecars
// (`src/vm/registry.ts`) and `listSessions()` silently skips malformed
// Gondolin metadata (confirmed by reading `session-registry.js`), so a
// corrupted file in either registry degrades to "that one row is missing",
// never a crash.
import { parseArgs } from "node:util";
import { listSessions, type SessionEntry } from "@earendil-works/gondolin";
import { listSessionSidecars, type SessionSidecar } from "../vm/registry.ts";

/** Which of the two registries knew about a session — see the module comment's three cases. */
export type SessionJoin = "both" | "gondolin-only" | "sidecar-only";

/**
 * What a joined row's liveness means:
 * - `running` — Gondolin's registry has this session and reports `alive`
 *   (its own `isPidAlive(pid) && isSocketAlive(socketPath)`).
 * - `stale` — Gondolin's registry has it, but it is not alive: a leftover
 *   registry entry for a session whose process or socket is gone.
 * - `orphaned` — only Corb's sidecar has it. Gondolin's registry never knew
 *   about it or has already been gc'd; the session is definitively not
 *   running.
 */
export type SessionStatus = "running" | "stale" | "orphaned";

/** One session as seen across both registries. Exactly one of `gondolin`/`sidecar` may be `undefined`, never both. */
export interface JoinedSession {
  /** The join key — Gondolin's `vm.id` and the sidecar's filename stem (`src/vm/registry.ts`). */
  id: string;
  join: SessionJoin;
  status: SessionStatus;
  /** ISO 8601 — Gondolin's `createdAt` when it has an entry, otherwise the sidecar's `startedAt`. Also the sort key. */
  startedAt: string;
  gondolin: SessionEntry | undefined;
  sidecar: SessionSidecar | undefined;
}

/** `Date.parse`, with an unparseable timestamp sorting as oldest rather than poisoning the comparison with `NaN`. */
function timestamp(iso: string): number {
  const parsed = Date.parse(iso);
  return Number.isNaN(parsed) ? 0 : parsed;
}

/**
 * Pure join of Gondolin's own session entries with Corb's sidecars, keyed by
 * exact `id`. Handles all three cases in the module comment; never drops a
 * row from either side. Sorted newest-first (matching `listSessions()`'s own
 * `createdAt`-descending order, extended to cover sidecar-only rows it can't
 * know about), with `id` as a deterministic tie-break so identical timestamps
 * don't produce a run-to-run-unstable listing.
 */
export function joinSessions(entries: readonly SessionEntry[], sidecars: readonly SessionSidecar[]): JoinedSession[] {
  const sidecarsById = new Map(sidecars.map((sidecar) => [sidecar.id, sidecar]));
  const rows: JoinedSession[] = [];
  const matched = new Set<string>();

  for (const entry of entries) {
    const sidecar = sidecarsById.get(entry.id);
    if (sidecar !== undefined) {
      matched.add(entry.id);
    }
    rows.push({
      id: entry.id,
      join: sidecar !== undefined ? "both" : "gondolin-only",
      status: entry.alive ? "running" : "stale",
      startedAt: entry.createdAt,
      gondolin: entry,
      sidecar,
    });
  }

  for (const sidecar of sidecars) {
    if (matched.has(sidecar.id)) {
      continue;
    }
    rows.push({
      id: sidecar.id,
      join: "sidecar-only",
      status: "orphaned",
      startedAt: sidecar.startedAt,
      gondolin: undefined,
      sidecar,
    });
  }

  rows.sort((a, b) => timestamp(b.startedAt) - timestamp(a.startedAt) || a.id.localeCompare(b.id));
  return rows;
}

/**
 * Compact relative age of an ISO 8601 timestamp, largest whole unit only
 * (`45s`, `3m`, `2h`, `5d`) — enough to tell sessions apart at a glance,
 * which is all the human table needs; `--json` carries the exact timestamps
 * for anything that needs arithmetic. `now` is a parameter, never
 * `Date.now()` (see the module comment). An unparseable timestamp renders
 * `?` rather than `NaN`, and a timestamp in the future (host clock skew)
 * clamps to `0s` rather than rendering a negative age.
 */
export function formatAge(startedAt: string, now: number): string {
  const started = Date.parse(startedAt);
  if (Number.isNaN(started)) {
    return "?";
  }
  const seconds = Math.floor(Math.max(0, now - started) / 1000);
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h`;
  }
  return `${Math.floor(hours / 24)}d`;
}

/**
 * Shortest id prefix worth showing: at least `minWidth` characters, grown
 * only as far as needed to keep every listed id distinct. Session ids are
 * 36-character UUIDs, and Gondolin's own `findSession()` accepts any
 * unambiguous prefix (confirmed in `session-registry.js`), so a short prefix
 * is genuinely useful to copy for the later `corb attach`/`corb kill` items
 * — not merely narrower. Returns the full length when no prefix at
 * `minWidth`-or-longer separates the ids (in practice unreachable: 12 hex
 * characters of a v4 UUID colliding across a handful of local sessions).
 */
export function idColumnWidth(ids: readonly string[], minWidth = 12): number {
  const longest = ids.reduce((max, id) => Math.max(max, id.length), 0);
  for (let width = minWidth; width < longest; width++) {
    if (new Set(ids.map((id) => id.slice(0, width))).size === ids.length) {
      return width;
    }
  }
  // Either no prefix shorter than the full id separated them, or every id is
  // already shorter than `minWidth` (so the loop never ran) — the full length
  // is correct for both, and is the only width that cannot collide.
  return longest;
}

/** Placeholder for a column a row genuinely has no value for — an unmatched Gondolin entry has no workspace/image, and fabricating one would be worse than saying so. */
const ABSENT = "-";

const HEADERS = ["ID", "STATUS", "AGE", "WORKSPACE", "IMAGE", "LABEL"];

function toRow(session: JoinedSession, idWidth: number, now: number): string[] {
  const { sidecar, gondolin } = session;
  const workspace = sidecar !== undefined && sidecar.dirs.length > 0 ? sidecar.dirs.map((dir) => dir.name).join(",") : ABSENT;
  return [
    session.id.slice(0, idWidth),
    session.status,
    formatAge(session.startedAt, now),
    workspace,
    sidecar?.image.selector ?? ABSENT,
    // Corb's sidecar and Gondolin's registry hold the same label for a
    // session Corb started (`runSession()` passes it as `VM.create()`'s
    // `sessionLabel`), so the fallback only matters for a gondolin-only row
    // — where it is the single most identifying thing available.
    sidecar?.sessionLabel ?? gondolin?.label ?? ABSENT,
  ];
}

/** Pads every cell to its column's widest entry (headers included) and joins with two spaces. Trailing whitespace is trimmed so the last column never pads out to nothing visible. */
function renderTable(rows: readonly string[][]): string[] {
  const widths = HEADERS.map((header, column) => rows.reduce((max, row) => Math.max(max, row[column]?.length ?? 0), header.length));
  return [HEADERS, ...rows].map((row) => row.map((cell, column) => cell.padEnd(widths[column] ?? 0)).join("  ").trimEnd());
}

/**
 * Human-readable listing: an aligned table, then a note whenever any row is
 * not running — that note is where a reader is told, at the moment they first
 * see a `stale`/`orphaned` row, that this command did not and will not delete
 * it. A completely empty registry pair gets a plain sentence, not a bare
 * header row over nothing.
 */
export function renderLsText(sessions: readonly JoinedSession[], now: number): string {
  if (sessions.length === 0) {
    return "corb ls: no sessions.";
  }
  const idWidth = idColumnWidth(sessions.map((session) => session.id));
  const lines = renderTable(sessions.map((session) => toRow(session, idWidth, now)));
  const notRunning = sessions.filter((session) => session.status !== "running").length;
  if (notRunning > 0) {
    lines.push(
      "",
      `corb ls: ${notRunning} of ${sessions.length} session(s) not running — 'stale' is a leftover Gondolin registry entry, ` +
        "'orphaned' is a leftover corb sidecar for a session that ended without clean teardown. " +
        "Nothing was deleted: corb ls only reads.",
    );
  }
  return lines.join("\n");
}

/** One session in `--json` output. Both registries' full records are carried verbatim (`null` when that side has no entry) so a script never has to re-read either registry itself. */
export interface LsSessionJson {
  id: string;
  join: SessionJoin;
  status: SessionStatus;
  startedAt: string;
  gondolin: SessionEntry | null;
  sidecar: SessionSidecar | null;
}

/** The JSON payload `renderLsJson` serializes. An object rather than a bare array so a later item can add a sibling field without breaking every existing consumer's parse. */
export interface LsJson {
  sessions: LsSessionJson[];
}

/** Machine-readable listing, pretty-printed — same convention as `src/config/render.ts`'s `renderJson` (`JSON.stringify(payload, null, 2)`, a named exported payload interface). */
export function renderLsJson(sessions: readonly JoinedSession[]): string {
  const payload: LsJson = {
    sessions: sessions.map((session) => ({
      id: session.id,
      join: session.join,
      status: session.status,
      startedAt: session.startedAt,
      gondolin: session.gondolin ?? null,
      sidecar: session.sidecar ?? null,
    })),
  };
  return JSON.stringify(payload, null, 2);
}

export interface LsCommandArgs {
  json: boolean;
}

export function parseLsArgs(argv: string[]): LsCommandArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { json: { type: "boolean" } },
    // Positionals are accepted by the parser and rejected here, rather than
    // banned via `allowPositionals: false`, purely so the error names the
    // command and the offending argument — matching `parseExplainArgs`'s own
    // handling of an extra positional.
    allowPositionals: true,
    strict: true,
  });

  if (positionals.length > 0) {
    throw new Error(`corb ls: unexpected argument '${positionals[0]}' (corb ls takes no positional arguments)`);
  }
  return { json: values.json ?? false };
}

/**
 * The only function here that touches real global state: the real Gondolin
 * session registry, the real sidecar directory, and the real clock.
 *
 * `listSessions()` can be slow when dead sessions are lying around — its
 * liveness check is a real socket connect with a 500ms timeout, per dead
 * socket, serially (`session-registry.js`). That is the SDK's behavior, not
 * something this command caches around: a stale cache of "is this session
 * alive" is worse than a listing that occasionally takes a moment.
 */
export async function runLsCommand(argv: string[]): Promise<void> {
  const args = parseLsArgs(argv);
  const sessions = joinSessions(await listSessions(), listSessionSidecars());
  console.log(args.json ? renderLsJson(sessions) : renderLsText(sessions, Date.now()));
}
