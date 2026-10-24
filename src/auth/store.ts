// `src/auth/store.ts` — host-side storage for host-brokered OAuth logins
// (ADR 0012). One JSON file per provider under a credentials directory
// (`src/config/paths.ts`'s `credentialsStateDir()`, i.e.
// `$CORB_STATE_DIR/credentials/<provider>.json`), shared by every corb
// process on the host.
//
// These files hold real credentials — an OAuth access token and, more
// valuable, a refresh token that outlives any one session — so:
//
// - Every write goes through `writeFileSecure` (`src/util/secure-write.ts`):
//   temp-file-then-rename, so a reader never sees a torn file, and the file
//   is 0600 from the moment it exists.
// - The directory itself is forced to 0700 on every write, not only when this
//   module happens to create it. It is corb's own directory, so tightening a
//   looser mode someone left behind is always correct.
// - The directory lives under corb's state directory, which `corb run`
//   already refuses to mount into a guest (`docs/security.md`, "Configuration
//   boundary"), so a guest can never read it.
//
// Refresh tokens may rotate on every refresh. Two corb sessions refreshing
// with the same refresh token at the same time could leave one of them (or
// the stored file) holding a token the provider has already invalidated.
// `withCredentialLock` below serialises refreshes across processes with a
// lock file next to the credential file; the caller (`src/auth/broker.ts`)
// re-reads the file after taking the lock, so a process that waited picks up
// the other process's fresh token instead of refreshing again.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { writeFileSecure } from "../util/secure-write.ts";

/** Current on-disk format version. Bumped only on an incompatible change. */
export const CREDENTIAL_FILE_VERSION = 1;

/**
 * One provider's stored OAuth login. `expires` is a Unix timestamp in
 * milliseconds (matching Pi's own `auth.json` convention), after which
 * `access` must be refreshed. `accountId` is provider-specific metadata that
 * is not itself a secret (for `openai-codex`, the ChatGPT account id Pi also
 * sends in a plain header).
 */
export interface StoredCredential {
  version: typeof CREDENTIAL_FILE_VERSION;
  provider: string;
  type: "oauth";
  access: string;
  refresh: string;
  expires: number;
  accountId?: string;
  /** ISO timestamp of the last login or refresh. Informational only. */
  updatedAt: string;
}

/** Thrown for a provider id that is not safe to use as a file name. */
export class InvalidProviderIdError extends Error {
  constructor(providerId: string) {
    super(`corb auth: invalid provider id '${providerId}' (expected lowercase letters, digits and '-')`);
    this.name = "InvalidProviderIdError";
  }
}

/** Thrown when a stored credential file exists but cannot be used. */
export class CredentialFileError extends Error {
  constructor(filePath: string, reason: string, providerId: string) {
    super(
      `corb auth: stored login at '${filePath}' is unusable (${reason}).\n` +
        `  Run 'corb logout ${providerId}' and then 'corb login ${providerId}' to replace it.`,
    );
    this.name = "CredentialFileError";
  }
}

/** Thrown when the refresh lock cannot be taken within the timeout. */
export class CredentialLockTimeoutError extends Error {
  constructor(lockPath: string) {
    super(
      `corb auth: timed out waiting for the credential lock '${lockPath}'. ` +
        "Another corb process may be stuck refreshing; if none is running, delete the lock file.",
    );
    this.name = "CredentialLockTimeoutError";
  }
}

// Provider ids become file names, so they must be a single, plain path
// segment. A registry id is always this shape; the check exists so a
// mistyped CLI argument can never reach path construction.
const PROVIDER_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

export function assertValidProviderId(providerId: string): void {
  if (!PROVIDER_ID_RE.test(providerId)) {
    throw new InvalidProviderIdError(providerId);
  }
}

/** Path to `providerId`'s credential file inside `dir`. */
export function credentialFilePath(dir: string, providerId: string): string {
  assertValidProviderId(providerId);
  return path.join(dir, `${providerId}.json`);
}

function lockFilePath(dir: string, providerId: string): string {
  return `${credentialFilePath(dir, providerId)}.lock`;
}

function isEnoent(err: unknown): boolean {
  return err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT";
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * Validates parsed JSON as a `StoredCredential` for `providerId`. Returns the
 * failure reason, or `undefined` when the value is valid. Never echoes a
 * field's value back into the reason — these are secrets.
 */
function validateStoredCredential(value: unknown, providerId: string): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "not a JSON object";
  }
  const record = value as Record<string, unknown>;
  if (record.version !== CREDENTIAL_FILE_VERSION) {
    return `unsupported version (expected ${CREDENTIAL_FILE_VERSION})`;
  }
  if (record.provider !== providerId) {
    return "provider field does not match the file name";
  }
  if (record.type !== "oauth") {
    return "type is not 'oauth'";
  }
  if (!isNonEmptyString(record.access) || !isNonEmptyString(record.refresh)) {
    return "access or refresh token missing";
  }
  if (typeof record.expires !== "number" || !Number.isFinite(record.expires)) {
    return "expires is not a finite number";
  }
  if (record.accountId !== undefined && !isNonEmptyString(record.accountId)) {
    return "accountId is not a non-empty string";
  }
  if (typeof record.updatedAt !== "string") {
    return "updatedAt is not a string";
  }
  return undefined;
}

/**
 * Reads `providerId`'s stored login from `dir`. `undefined` means "not logged
 * in" (no file). A file that exists but is malformed throws
 * `CredentialFileError` rather than reading as "not logged in": silently
 * treating a corrupt file as absent would hide the problem behind a
 * misleading "run corb login" message the user already followed.
 */
export function readStoredCredential(dir: string, providerId: string): StoredCredential | undefined {
  const filePath = credentialFilePath(dir, providerId);
  let text: string;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    if (isEnoent(err)) {
      return undefined;
    }
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CredentialFileError(filePath, "not valid JSON", providerId);
  }
  const problem = validateStoredCredential(parsed, providerId);
  if (problem !== undefined) {
    throw new CredentialFileError(filePath, problem, providerId);
  }
  return parsed as StoredCredential;
}

/** Ensures `dir` exists with mode 0700, tightening it if it already exists — see the module comment. */
function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
}

/** Writes `credential` atomically with mode 0600 into `dir` (forced to 0700). */
export function writeStoredCredential(dir: string, credential: StoredCredential): void {
  const filePath = credentialFilePath(dir, credential.provider);
  ensurePrivateDir(dir);
  writeFileSecure(filePath, `${JSON.stringify(credential, null, 2)}\n`);
}

/** Deletes `providerId`'s stored login. Returns whether a file was actually removed. */
export function deleteStoredCredential(dir: string, providerId: string): boolean {
  const filePath = credentialFilePath(dir, providerId);
  try {
    fs.unlinkSync(filePath);
    return true;
  } catch (err) {
    if (isEnoent(err)) {
      return false;
    }
    throw err;
  }
}

export interface CredentialLockOptions {
  /** How long to wait for another holder before giving up. Default 60s. */
  timeoutMs?: number;
  /**
   * Age after which a lock is considered abandoned and may be taken over.
   * Default 120s. Must stay well above the longest time a holder keeps the
   * lock — the broker bounds each refresh request with its own timeout, far
   * below this.
   */
  staleMs?: number;
  /** Injectable for tests. */
  now?: () => number;
  /** Injectable for tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable for tests. Default: `process.kill(pid, 0)`. */
  isProcessAlive?: (pid: number) => boolean;
}

interface LockFileContent {
  pid: number;
  token: string;
  createdAt: number;
}

function defaultIsProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: the pid exists but belongs to someone else — still alive.
    return err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readLockFile(lockPath: string): { content: LockFileContent | undefined; mtimeMs: number } | undefined {
  let stat: fs.Stats;
  let text: string;
  try {
    stat = fs.statSync(lockPath);
    text = fs.readFileSync(lockPath, "utf8");
  } catch (err) {
    if (isEnoent(err)) {
      return undefined;
    }
    throw err;
  }
  try {
    const parsed = JSON.parse(text) as Partial<LockFileContent>;
    if (typeof parsed.pid === "number" && typeof parsed.token === "string" && typeof parsed.createdAt === "number") {
      return { content: parsed as LockFileContent, mtimeMs: stat.mtimeMs };
    }
  } catch {
    // Fall through: a lock file caught mid-write, or garbage.
  }
  return { content: undefined, mtimeMs: stat.mtimeMs };
}

/**
 * Runs `fn` while holding an exclusive, cross-process lock for `providerId`'s
 * credential file in `dir`. The lock is a sibling `<provider>.json.lock` file
 * created with `O_EXCL` (`"wx"`), which is atomic on a local filesystem.
 *
 * A lock is taken over when its holder is gone: its pid is no longer alive
 * on this host, or it is older than `staleMs` (covers a pid that was reused,
 * or a lock written from another pid namespace). The takeover renames the
 * stale file away before retrying the `O_EXCL` create. Two waiters that both
 * decide the same lock is stale in the same instant can still race; that
 * needs a crashed holder plus two contenders within milliseconds, and the
 * worst outcome is one redundant refresh, which the provider either accepts
 * or rejects with a clear "log in again" error.
 */
export async function withCredentialLock<T>(
  dir: string,
  providerId: string,
  fn: () => Promise<T>,
  options: CredentialLockOptions = {},
): Promise<T> {
  const lockPath = lockFilePath(dir, providerId);
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const isProcessAlive = options.isProcessAlive ?? defaultIsProcessAlive;
  const timeoutMs = options.timeoutMs ?? 60_000;
  const staleMs = options.staleMs ?? 120_000;
  const token = randomUUID();
  const deadline = now() + timeoutMs;

  ensurePrivateDir(dir);

  let delayMs = 25;
  for (;;) {
    try {
      const content: LockFileContent = { pid: process.pid, token, createdAt: now() };
      fs.writeFileSync(lockPath, JSON.stringify(content), { flag: "wx", mode: 0o600 });
      break;
    } catch (err) {
      if (!(err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "EEXIST")) {
        throw err;
      }
    }

    const existing = readLockFile(lockPath);
    if (existing !== undefined) {
      const age = now() - (existing.content?.createdAt ?? existing.mtimeMs);
      const holderGone = existing.content !== undefined && !isProcessAlive(existing.content.pid);
      if (holderGone || age > staleMs) {
        try {
          fs.renameSync(lockPath, `${lockPath}.stale-${randomUUID()}`);
        } catch (err) {
          if (!isEnoent(err)) {
            throw err;
          }
        }
        removeStaleLockFiles(dir, path.basename(lockPath));
        continue;
      }
    }

    if (now() >= deadline) {
      throw new CredentialLockTimeoutError(lockPath);
    }
    await sleep(delayMs);
    delayMs = Math.min(delayMs * 2, 500);
  }

  try {
    return await fn();
  } finally {
    // Release only our own lock. If ours was judged stale and taken over
    // (which `staleMs` is sized to make impossible in practice), deleting
    // the new holder's lock would let a third process in alongside it.
    const current = readLockFile(lockPath);
    if (current?.content?.token === token) {
      fs.rmSync(lockPath, { force: true });
    }
  }
}

/** Best-effort removal of renamed-away stale lock files. */
function removeStaleLockFiles(dir: string, lockBaseName: string): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.startsWith(`${lockBaseName}.stale-`)) {
      fs.rmSync(path.join(dir, entry), { force: true });
    }
  }
}
