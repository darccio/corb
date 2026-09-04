// `src/util/secure-write.ts` — a shared helper for replacing a whole file's
// contents on disk, both atomically and with restrictive permissions.
//
// Two on-disk state files used to call `fs.writeFileSync` directly and
// nothing else: `src/config/resolve.ts`'s `trusted.json` (via
// `acceptWorkspace`) and `src/vm/registry.ts`'s session sidecars (via
// `writeSessionSidecar`). That left both with two problems. First,
// permissions: the default file mode (0644 under a typical umask — world
// readable) on data that is only ever meant for the user who owns it, not
// every other local account on the machine — a session sidecar alone holds
// `dirs[].hostPath`, the audit log path, the host `corb run` pid, and, for a
// `--expose` session, the live, host-reachable ingress URL into the guest.
// Second, atomicity: `writeFileSync` truncates the target file in place, so
// a crash or `SIGKILL` mid-write leaves a torn, partially-written file
// behind. `resolve.ts`'s own `validateTrustStoreShape` already anticipates
// that second failure mode by name — a torn write is one of the two causes
// it names for a corrupted trust store — and `readTrustStore` runs on the
// path of every `corb run`/`corb explain`, for every workspace, not just the
// one being written. A torn `trusted.json` doesn't just lose the one record
// being written; it bricks the whole config system until someone manually
// deletes the file.
//
// `src/policy/audit.ts`'s `ensureOpen` already hardens a sibling file in the
// same general state-directory area to the same 0600 file / 0700 directory
// permissions, but its mechanism is deliberately not reused here: it opens
// one fd once and appends to it for the life of a session, where this
// module replaces a file's entire content in one shot, each call. The
// permission *goal* is shared in spirit; the write mechanism has to differ.
//
// The mechanism here is temp-file-then-rename: write the new content to a
// freshly-created, already-0600 temp file in the same directory as the
// target (same directory is required — POSIX `rename()` is only atomic
// within a single filesystem; a temp file elsewhere would make the final
// step either fail across devices or silently fall back to a non-atomic
// copy-then-delete), then `rename()` it onto the target path. A reader never
// observes a partial write — the target either still holds its old, complete
// content, or its new, complete content, since `rename()` swaps the
// directory entry in a single step — and a crash before the rename completes
// leaves the original target completely untouched, never torn.
//
// This also gets the permission goal essentially for free, and with a
// property `audit.ts`'s own approach doesn't have: since `rename()` replaces
// the target's directory entry with the temp file's inode outright, the temp
// file's own permissions (0600, set at its creation) travel with it — there
// is no separate, retroactive `chmodSync` step needed to tighten a
// pre-existing, more-permissive file at the target path, unlike
// `ensureOpen`'s append-mode `openSync`, whose `mode` argument is silently
// ignored when the target file already exists.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

/**
 * Writes `content` to `filePath`, replacing whatever was there, atomically
 * and with restrictive permissions (0600 on the file) — see the module
 * comment for the full rationale and mechanism.
 *
 * Creates any missing ancestor directories first
 * (`fs.mkdirSync(dir, { recursive: true, mode: 0o700 })`) — as with
 * `src/policy/audit.ts`'s identical `ensureOpen` call, `recursive: true` is
 * a no-op for a directory that already exists, so this only sets `0o700` on
 * a directory this call itself creates; an existing, more permissive
 * directory is left exactly as it was.
 *
 * On any failure before the rename completes, removes the temp file
 * (best-effort — a failure to clean it up does not mask or replace the
 * original error) and rethrows, leaving `filePath` exactly as it was before
 * this call: unchanged if it already existed, still absent if it didn't.
 */
export function writeFileSecure(filePath: string, content: string): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const tempPath = path.join(dir, `.${path.basename(filePath)}.tmp-${process.pid}-${randomUUID()}`);
  try {
    fs.writeFileSync(tempPath, content, { mode: 0o600 });
    fs.renameSync(tempPath, filePath);
  } catch (err) {
    try {
      fs.rmSync(tempPath, { force: true });
    } catch {
      // Best-effort cleanup only. If removal itself fails too, the original
      // `err` below is what the caller needs to see — not a cleanup failure
      // masking it.
    }
    throw err;
  }
}
