// `src/policy/checks.ts` — M7.2: the fixed, host-authored content-check
// functions `docs/design.md` §5 describes as "fixed functions versioned in
// Corb's own repository: secret-shaped patterns in the diff, a
// changed-file-count ceiling, path rules duplicated from §3 as a second
// look on the content path. None of them are guest-configurable, and none
// of them shell out to anything constructed from the payload."
//
// This module also owns the wire contract fixed by the guest side (M7.1,
// `guest/internal/gate/hostcheck.go`) — `PolicyCheckRequest`, `Violation`,
// `PolicyCheckResponse` — since `checks.ts` is where callers of that
// contract (both this file's own `runChecks` and `sentinel.ts`, which parses
// the request and serializes the response) already have to look. Keeping
// the three types here, rather than splitting them across the two files
// that use them, means there is exactly one place their JSON field names
// (deliberately camelCase, matching `hostcheck.go`'s own `json:"..."` tags)
// can drift from the guest's Go structs.
//
// Every function here is pure: no I/O, no clock, no randomness, nothing
// read from `process.env`. `sentinel.ts` is the only thing in this
// milestone that touches a `Request`/`Response` or the outside world at
// all — this file is deliberately independently unit-testable with nothing
// but plain data in and plain data out.
//
// Deliberately does NOT import from `../vm/session.ts`: once M7.3 wires
// `sentinel.ts` into `session.ts`'s own dependency chain (via
// `src/vm/egress.ts`, see that file's forward-pointer comment), a dependency
// from this file (which `sentinel.ts` imports) back into `session.ts` would
// be circular. `checkDuplicatedPathRules` only needs `globToRegExp`
// (`../vfs/glob.ts`, a leaf module with no imports of its own) and the
// already-merged `DirConfig[]` the caller hands it — nothing session-shaped.
import type { DirConfig, EffectivePolicyConfig } from "../config/load.ts";
import { globToRegExp } from "../vfs/glob.ts";

// ---------------------------------------------------------------------------
// Wire contract (fixed by M7.1 — `guest/internal/gate/hostcheck.go`)
// ---------------------------------------------------------------------------

/**
 * POSTed as JSON by the guest's `policygate` to `policy.corb.invalid`
 * (`sentinel.ts`). Field names and shape are fixed by
 * `guest/internal/gate/hostcheck.go`'s `PolicyCheckRequest` — do not rename
 * or restructure without updating that Go struct in lockstep.
 */
export interface PolicyCheckRequest {
  op: "git.commit" | "git.push";
  changedFiles: string[];
  diff: string;
}

/**
 * One content-check finding. `file` is omitted entirely (not present as a
 * JSON key, not `null`) when a violation isn't about one specific file —
 * matches `hostcheck.go`'s `File string \`json:"file,omitempty"\``.
 */
export interface Violation {
  rule: string;
  message: string;
  hint: string;
  file?: string;
}

/**
 * `sentinel.ts`'s response envelope. Shape is fixed by `hostcheck.go`'s own
 * `PolicyCheckResponse` (that file's comment: "docs/design.md §5 fixes the
 * request shape and the Violation type verbatim but does not fix a response
 * envelope, so this is designed here"). Exactly one of three outcomes:
 *
 *   - `allowed: true` — proceed. `violations`/`rateLimited` are ignored by
 *     the guest.
 *   - `allowed: false, rateLimited: true` — denied because the session
 *     exhausted its check budget. `violations` must be omitted: content was
 *     never actually inspected.
 *   - `allowed: false, rateLimited: false` — denied because `violations`
 *     lists one or more real content problems. Never both `rateLimited` and
 *     a populated `violations` at once.
 */
export interface PolicyCheckResponse {
  allowed: boolean;
  rateLimited: boolean;
  violations?: Violation[];
}

// ---------------------------------------------------------------------------
// scanForSecrets
// ---------------------------------------------------------------------------

/**
 * One secret-shaped regex plus the human-readable kind name used in a
 * violation's `message`. Not exported: `SECRET_PATTERNS` below is the
 * complete, fixed list a caller should ever need.
 */
interface SecretPattern {
  kind: string;
  regex: RegExp;
}

/**
 * A small, fixed, documented set of secret-shaped patterns. Per
 * `docs/design.md` §5, this is deliberately "secret-shaped patterns in the
 * diff", not an exhaustive entropy-based scanner — modest and auditable, not
 * a giant regex zoo. Three patterns, chosen because each is both a common,
 * real credential shape *and* has a genuinely low false-positive rate (no
 * pattern here would plausibly match ordinary source code or prose):
 *
 *   1. **AWS access key ID** — `AKIA` (long-term) or `ASIA` (temporary/STS)
 *      followed by exactly 16 uppercase-alnum characters. This exact shape
 *      is M7's own acceptance-test case (`docs/design.md` §10: "A commit
 *      containing a secret-shaped string is blocked"), so it must be exact:
 *      neither the prefix nor the length is a guess.
 *   2. **PEM private-key header** — `-----BEGIN`, an optional key-type word
 *      (`RSA`, `EC`, `DSA`, `OPENSSH`), then `PRIVATE KEY-----`. Catches a
 *      pasted private key regardless of its type, without trying to
 *      validate the base64 body that follows (the header alone is already
 *      unambiguous — nothing else legitimately starts a line that way).
 *   3. **GitHub token prefixes** — `ghp_`/`gho_`/`ghs_`/`ghr_` (personal
 *      access token, OAuth token, server-to-server token, refresh token)
 *      each followed by 20+ alphanumeric characters, or the newer
 *      `github_pat_` fine-grained token prefix followed by 20+
 *      alphanumeric/underscore characters. The minimum-length tail keeps
 *      this from firing on, say, a variable literally named `ghp_test` in
 *      a short test fixture.
 *
 * Deliberately stopping here rather than growing this into a general
 * entropy scanner or a big vendor-specific pattern library: every addition
 * to this list is a permanent maintenance and false-positive surface, and
 * per §5 this check is one layer among several (the primary enforcement for
 * *paths* is §3's kernel-facing VFS layer; this is a content-shaped
 * second-order check). A workspace with a specific, known secret shape it
 * cares about is better served by not committing it at all than by this
 * list trying to anticipate every credential format that exists.
 */
const SECRET_PATTERNS: readonly SecretPattern[] = [
  { kind: "AWS access key ID", regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { kind: "PEM private key", regex: /-----BEGIN(?: (?:RSA|EC|DSA|OPENSSH))? PRIVATE KEY-----/g },
  {
    kind: "GitHub token",
    regex: /\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  },
];

/**
 * Scans `diff` for the fixed set of secret-shaped patterns above. Returns
 * one `Violation` (`rule: "secret-in-diff"`) per distinct match — a diff
 * with two AWS-shaped keys and one GitHub token produces three violations,
 * not one. `message` names the kind of secret it looks like but never
 * includes the matched substring itself: this response crosses back into
 * the guest's own stderr transcript (and possibly the agent's own context,
 * which may get logged or summarized further), so the actual credential
 * value is never echoed back into it, purely as a caution — unlike a
 * network hop, this direction (host response -> guest) isn't itself an
 * exfiltration channel, but there is no reason to be careless with it
 * either.
 */
export function scanForSecrets(diff: string): Violation[] {
  const violations: Violation[] = [];
  for (const { kind, regex } of SECRET_PATTERNS) {
    // Each pattern object owns a `g`-flagged RegExp with its own `lastIndex`
    // state; `matchAll` on a fresh-per-call iterator is fine to reuse across
    // calls to this function since `matchAll` does not mutate the regex
    // passed to it (it clones internally), unlike `regex.exec`/`test` in a
    // loop.
    for (const _match of diff.matchAll(regex)) {
      violations.push({
        rule: "secret-in-diff",
        message: `diff contains what looks like a ${kind}`,
        hint: "remove the credential from the diff and rotate it if it was ever committed",
      });
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
// checkChangedFileCeiling
// ---------------------------------------------------------------------------

/**
 * Denies a change that touches more than `ceiling` files. `ceiling ===
 * undefined` (`policy["max-changed-files"]` unset — there is no built-in
 * default per `src/config/load.ts`'s `BUILTIN_DEFAULTS` comment) means "no
 * ceiling configured": always returns `undefined`, never denies.
 */
export function checkChangedFileCeiling(
  changedFiles: string[],
  ceiling: number | undefined,
): Violation | undefined {
  if (ceiling === undefined) {
    return undefined;
  }
  if (changedFiles.length > ceiling) {
    return {
      rule: "max-changed-files",
      message: `this change touches ${changedFiles.length} files, exceeding the configured ceiling of ${ceiling}`,
      hint: "split this into smaller commits, or raise policy.max-changed-files in config.toml if this is expected",
    };
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// checkDuplicatedPathRules
// ---------------------------------------------------------------------------

/**
 * `docs/design.md` §5's "path rules duplicated from §3 as a second look on
 * the content path". `PolicyCheckRequest` has no field identifying which
 * `/work/<name>` directory the git repo the guest ran `git commit`/`git
 * push` in actually lives under (`guest/internal/gate/collect.go` never
 * learns or sends that — it only knows the repo's own working tree), so
 * this cannot precisely scope its check to the one directory the change
 * actually happened in. Instead it checks every entry in `changedFiles`
 * against the **union** of every `hidden`/`deny-write` rule glob across
 * every configured directory in `dirs`.
 *
 * This is coarse and best-effort by construction, mirroring
 * `collectPushRange`'s own documented heuristic in
 * `guest/internal/gate/collect.go`: a changed file path that happens to
 * match a rule glob belonging to a *different*, unrelated workspace
 * directory produces a false positive here. That is an accepted, low-cost
 * failure mode, not a bug to chase down — this check is explicitly a
 * redundant "second look" (`docs/design.md` §5's own division-of-labour
 * table: content checks are "good for... content rules", not primary path
 * enforcement), not the primary enforcement mechanism. The primary,
 * precise, unbypassable enforcement for *where* a path is writable is §3's
 * kernel-facing `GlobPolicyProvider`, already built (M5) and running below
 * the guest kernel's view of the filesystem regardless of what this check
 * does or misses.
 *
 * One `Violation` per matched *file* (`rule: "path-rule-duplicate"`, `file`
 * set to that path): if more than one rule across `dirs` would match the
 * same file, only the first match (in `dirs`/`rules` iteration order) is
 * reported for that file, since the point is to flag the file, not to
 * enumerate every rule that happens to overlap it.
 */
export function checkDuplicatedPathRules(
  changedFiles: string[],
  dirs: readonly DirConfig[],
): Violation[] {
  const candidateRules: { glob: string; mode: string; reason?: string }[] = [];
  for (const dir of dirs) {
    for (const rule of dir.rules) {
      if (rule.glob === undefined) {
        continue;
      }
      if (rule.mode === "hidden" || rule.mode === "deny-write") {
        candidateRules.push(
          rule.reason === undefined
            ? { glob: rule.glob, mode: rule.mode }
            : { glob: rule.glob, mode: rule.mode, reason: rule.reason },
        );
      }
    }
  }

  const violations: Violation[] = [];
  for (const file of changedFiles) {
    for (const rule of candidateRules) {
      if (globToRegExp(rule.glob).test(file)) {
        const reasonSuffix = rule.reason === undefined ? "" : ` — ${rule.reason}`;
        violations.push({
          rule: "path-rule-duplicate",
          message: `'${file}' matches a ${rule.mode} rule (${rule.glob})${reasonSuffix}`,
          hint: "this path is restricted by workspace policy; revert this change or discuss it with the workspace owner",
          file,
        });
        break;
      }
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
// runChecks
// ---------------------------------------------------------------------------

/**
 * Runs every enabled check against one `PolicyCheckRequest` and concatenates
 * their violations. Dispatch:
 *
 *   - `scanForSecrets` runs only when `policy["secret-scan"]` is `true` —
 *     the one check with its own config toggle.
 *   - `checkChangedFileCeiling` and `checkDuplicatedPathRules` always run;
 *     `docs/design.md` does not gate either behind a separate flag (a
 *     `checkChangedFileCeiling` call with `ceiling === undefined` is
 *     already a no-op on its own, and `checkDuplicatedPathRules` costs
 *     nothing extra to always run against whatever `dirs` the caller has).
 *
 * `dirs` is threaded straight through to `checkDuplicatedPathRules`; see
 * that function's doc comment for why the check itself, not this dispatcher,
 * is coarse.
 */
export function runChecks(
  req: PolicyCheckRequest,
  policy: EffectivePolicyConfig,
  dirs: readonly DirConfig[],
): Violation[] {
  const violations: Violation[] = [];

  if (policy["secret-scan"]) {
    violations.push(...scanForSecrets(req.diff));
  }

  const ceilingViolation = checkChangedFileCeiling(req.changedFiles, policy["max-changed-files"]);
  if (ceilingViolation !== undefined) {
    violations.push(ceilingViolation);
  }

  violations.push(...checkDuplicatedPathRules(req.changedFiles, dirs));

  return violations;
}
