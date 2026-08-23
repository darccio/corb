// `src/vm/gitssh.ts` — M4.1 builds the `ssh.execPolicy` piece of
// `docs/design.md` §4's git gate: the *real* enforcement point for
// git-over-SSH (fetch/clone allowed only against `git.allow-repos`, push
// gated by `git.allow-push`), as opposed to the in-guest `policygate` shim
// (a later, non-security-boundary convenience layer over the same rules —
// see design.md §4's own framing: "a policy table in front of them is a
// convenience layer, not a security boundary" for anything that never
// leaves the guest). `ssh.execPolicy` is the opposite: it runs host-side,
// after the guest has already opened an SSH channel outward, and its
// decision is the actual gate — a bypass here really does reach a remote
// git host.
//
// This module exports three pure functions building up to one assembler:
//   - `normalizeRepo` — canonicalizes a repo path string for allowlist
//     comparison.
//   - `matchAnyGlob` — tests a normalized repo against `git.allow-repos`.
//   - `buildGitSshOptions` — assembles the real `SshOptions` object
//     (`@earendil-works/gondolin`) a later item (M4.3) will pass to
//     `VM.create({ ssh })`.
//
// Matches `src/vm/egress.ts`'s (M3.2/M3.3) own discipline exactly: pure
// functions, no I/O beyond the `env` object handed in, `NodeJS.ProcessEnv`
// injected rather than read from `process.env` directly (so tests never
// touch real environment state), dedicated `Error` subclasses with
// actionable messages. Like `buildSecretBindings` (M3.2) before
// `buildEgressConfig` (M3.3) added audit wiring one item later, this module
// takes no `AuditWriter` parameter — wiring `execPolicy`'s allow/deny
// decisions into the unified audit log (`src/policy/audit.ts`) is M4.3's
// job, once this module is actually threaded into `src/vm/session.ts`
// alongside `buildEgressConfig`. Nothing here is called from `session.ts`
// yet.
import { getInfoFromSshExecRequest, type SshExecDecision, type SshExecRequest, type SshOptions } from "@earendil-works/gondolin";
import type { EffectiveGitConfig } from "../config/load.ts";

/**
 * Thrown by `normalizeRepo` when `repo` contains `..`. A `..` segment is
 * never a legitimate part of a `owner/repo`-shaped path, and letting it
 * through normalization risks it later being compared against an allowlist
 * glob in some path-traversal-flavored way a future glob implementation
 * might not have foreseen. Failing closed here (reject outright, before any
 * allowlist comparison happens at all) is simpler to reason about and audit
 * than trying to normalize `..` away and hope every future caller of
 * `normalizeRepo`'s result treats "still contains .." as "obviously never
 * matches anything" correctly.
 *
 * In practice this is defense in depth, not the primary control:
 * `getInfoFromSshExecRequest` (`@earendil-works/gondolin`) already rejects
 * any SSH exec command whose repo argument contains `..` before Corb's
 * `execPolicy` ever sees it (`node_modules/@earendil-works/gondolin/dist/src/ssh/exec.js`:
 * `if (repo.includes("..")) return null;`), so `buildGitSshOptions`'s
 * `execPolicy` below never actually reaches this path via a real SSH
 * request. This error exists for `normalizeRepo`'s other callers (present
 * and future) that don't happen to sit behind that upstream check — for
 * example, normalizing `git.allow-repos` entries themselves.
 */
export class RepoTraversalError extends Error {
  constructor(repo: string) {
    super(`corb git: repo '${repo}' contains '..', which is never a valid path segment in a repository path.`);
    this.name = "RepoTraversalError";
  }
}

/**
 * Canonicalizes a repo path string (as returned by `GitSshExecInfo.repo`, or
 * as written in a `git.allow-repos` config entry) into the form
 * `matchAnyGlob` compares against: strips one leading `/`, strips one
 * trailing `.git`, lowercases the result.
 *
 * Throws `RepoTraversalError` if `repo` contains `..` anywhere — see that
 * class's own doc comment for why this fails closed rather than trying to
 * strip or escape the traversal segment.
 *
 * `~user/repo` (a real SSH-server-side shorthand for a *specific* user's
 * home-relative repo path — distinct from the `~/repo` current-user form,
 * which `getInfoFromSshExecRequest` already strips before Corb ever sees
 * the string) is deliberately NOT special-cased here: it is left as an
 * ordinary lowercase path segment, so `~user/repo` normalizes to exactly
 * `~user/repo`. Two reasons this is the right call rather than an
 * oversight:
 *   1. `getInfoFromSshExecRequest`'s own final shape check
 *      (`/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)+(?:\.git)?$/i`)
 *      rejects a leading `~` outright, so a `~user/repo`-shaped command
 *      never actually produces a `GitSshExecInfo.repo` value in the first
 *      place — this codepath is unreachable from a real SSH request, same
 *      as the `..` case above.
 *   2. Even so, a `git.allow-repos` entry is never written with a leading
 *      `~` in this codebase's own examples (`docs/design.md`'s
 *      `dario/corb`, `dario/*-docs`), so leaving `~user/repo` unmatched by
 *      any realistic allowlist entry is the fail-safe outcome by
 *      construction, without this function needing to special-case a form
 *      it will never actually be asked to normalize in practice.
 */
export function normalizeRepo(repo: string): string {
  if (repo.includes("..")) {
    throw new RepoTraversalError(repo);
  }
  let result = repo;
  if (result.startsWith("/")) {
    result = result.slice(1);
  }
  if (result.endsWith(".git")) {
    result = result.slice(0, -".git".length);
  }
  return result.toLowerCase();
}

/**
 * Converts one glob pattern into an anchored `RegExp`. Deliberately minimal:
 * `*` matches within a single path segment (never across `/`), which is the
 * only wildcard shape `git.allow-repos` actually needs
 * (`docs/design.md`'s own example: `dario/*-docs`). This is not a
 * general-purpose glob engine — no `**`, no `?`, no character classes — that
 * is `src/vfs/glob.ts`'s job once it exists (M5), for filesystem policy
 * globs that do need to cross path segments. Building that here would be
 * scope creep for a repo-name allowlist.
 */
function globToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .split("*")
    .map((segment) => segment.replace(/[.+^${}()|[\]\\]/g, "\\$&"))
    .join("[^/]*");
  return new RegExp(`^${escaped}$`);
}

/**
 * Tests whether `repo` (already `normalizeRepo`-normalized) matches any
 * glob in `patterns`.
 *
 * `patterns === undefined` — no `git.allow-repos` configured at all — means
 * "nothing matches", i.e. deny, not "everything matches". This is the same
 * asymmetry class as `egress.allow`'s `undefined`-vs-`[]` handling in
 * `src/vm/egress.ts`'s `buildEgressConfig`: an absent allowlist is not
 * license to allow everything, it is the strictest possible configuration.
 * An explicit `[]` produces the same result (`Array.prototype.some` on an
 * empty array is always `false`), so both are handled by the same code path
 * below rather than needing a separate check.
 *
 * Each pattern is lowercased before compiling, matching `normalizeRepo`'s
 * own lowercasing of `repo` — so `git.allow-repos = ["Dario/Corb"]` still
 * matches a repo argument that arrives as `dario/corb`. Patterns are
 * otherwise used exactly as configured: no leading-slash stripping, no
 * trailing-`.git` stripping, unlike `normalizeRepo`'s handling of the repo
 * side. `git.allow-repos` entries are operator-authored config, not
 * attacker-controlled SSH input, and applying `normalizeRepo`'s full
 * traversal-rejection/slash-stripping behavior to them risks silently
 * changing (or throwing on) something an operator deliberately wrote in
 * `config.toml`, for no matching security benefit.
 */
export function matchAnyGlob(patterns: string[] | undefined, repo: string): boolean {
  if (patterns === undefined) {
    return false;
  }
  return patterns.some((pattern) => globToRegExp(pattern.toLowerCase()).test(repo));
}

/** The two git-over-SSH services `execPolicy` below actually recognizes. Anything else is denied — see `buildGitSshOptions`'s doc comment. */
const GIT_UPLOAD_PACK = "git-upload-pack";
const GIT_RECEIVE_PACK = "git-receive-pack";

/**
 * Assembles the real `SshOptions` (`@earendil-works/gondolin`) a later item
 * (M4.3) will pass to `VM.create({ ssh })`. Three deliberate departures from
 * the plan's own §5.2 sketch, each verified against the shipped SDK rather
 * than trusted from the sketch — see the inline comments at each departure:
 *
 * 1. `allowedHosts` is never `git["allow-hosts"]` passed through unmodified;
 *    `?? []` is load-bearing (see the field's own comment below).
 * 2. `knownHostsFile` is deliberately left unset, not pointed at
 *    `~/.ssh/known_hosts` as the sketch suggested (see below).
 * 3. `execPolicy` denies a third case the sketch didn't call out: a
 *    recognized git SSH command whose *service* is neither
 *    `git-upload-pack` nor `git-receive-pack` (e.g. `git-upload-archive`).
 *    `docs/design.md` §1's allowlist-not-blocklist rule applies here just as
 *    much as it does to `git.allow-repos`: enumerating the two services
 *    Corb actually intends to support is finite, and defaulting an
 *    unrecognized-but-still-`git-*`-shaped service to *allow* would be the
 *    blocklist failure mode the rule warns against.
 */
export function buildGitSshOptions(git: EffectiveGitConfig, env: NodeJS.ProcessEnv): SshOptions {
  const execPolicy = (req: SshExecRequest): SshExecDecision => {
    const info = getInfoFromSshExecRequest(req);
    if (!info) {
      return {
        allow: false,
        message: "corb git: not a recognized git-over-ssh command (expected 'git-upload-pack' or 'git-receive-pack' against a single repo argument).",
      };
    }

    if (info.service !== GIT_UPLOAD_PACK && info.service !== GIT_RECEIVE_PACK) {
      return {
        allow: false,
        message: `corb git: ssh service '${info.service}' is not permitted (only fetch/clone and push are allowed).`,
      };
    }

    let repo: string;
    try {
      repo = normalizeRepo(info.repo);
    } catch (err) {
      return { allow: false, message: err instanceof Error ? err.message : String(err) };
    }

    if (!matchAnyGlob(git["allow-repos"], repo)) {
      return {
        allow: false,
        message: `corb git: repository '${info.repo}' is not in git.allow-repos.`,
      };
    }

    if (info.service === GIT_RECEIVE_PACK && !git["allow-push"]) {
      return {
        allow: false,
        message: "corb git: push is disabled for this session (set git.allow-push = true in config.toml to enable it).",
      };
    }

    return { allow: true };
  };

  const options: SshOptions = {
    // `SshOptions.allowedHosts` is a *required* `string[]`
    // (`node_modules/@earendil-works/gondolin/dist/src/qemu/ssh.d.ts`), not
    // optional like `createHttpHooks({ allowedHosts })` — there is no
    // "field omitted" state to worry about at the type level. But the value
    // this function must never do is pass `git["allow-hosts"]` through
    // unmodified when it's `undefined`, because `undefined` is not a legal
    // `string[]` here at all; `?? []` is required just to satisfy the type.
    // What makes this genuinely load-bearing rather than a type-satisfying
    // formality: confirmed by reading
    // `node_modules/@earendil-works/gondolin/dist/src/qemu/ssh.js`
    // (`createQemuSshInternals`), `const enabled = allowedTargets.length > 0`
    // — an empty `allowedHosts` array cleanly *disables SSH egress
    // entirely* (`isSshFlowAllowed` returns `false` for every flow when
    // `!ssh.enabled`), not a runtime error and not "allow all". That is the
    // *opposite* asymmetry direction from `createHttpHooks({ allowedHosts })`
    // (`docs/gondolin-notes.md` §4: omitting the field there means "allow
    // all"; `[]` means "deny all") — worth this comment specifically
    // because the two sit in the same codebase and are easy to misremember
    // against each other. Here, "no `git.allow-hosts` configured" and "SSH
    // egress is off" are the same value (`[]`) by construction, with no
    // separate "allow all" state reachable at all.
    allowedHosts: git["allow-hosts"] ?? [],
    execPolicy,
  };

  // `agent: git["ssh-agent"] ? env.SSH_AUTH_SOCK : undefined` per the plan's
  // sketch is not quite right under this project's `exactOptionalPropertyTypes`:
  // `SshOptions.agent?: string` means the property may be *absent*, not
  // that it may hold `undefined` — assigning `agent: undefined` explicitly
  // is a type error here, unlike a looser tsconfig. So the property is only
  // ever set when there is an actual socket path to set it to.
  //
  // If `git["ssh-agent"]` is `true` but `env.SSH_AUTH_SOCK` is unset, this
  // silently leaves `agent` absent rather than throwing. Two reasons, not
  // one: (1) `SshOptions.agent` is itself optional at the SDK level — a
  // missing agent socket is a normal, representable state, not a
  // programming error; (2) `corb doctor` (`src/commands/doctor.ts`, M3.5)
  // already has a dedicated, more informative check for exactly this
  // (`ssh-auth-sock`: warns when `SSH_AUTH_SOCK` is unset, and separately
  // when it's set but stale/nonexistent) — duplicating that as a hard error
  // here would both be redundant with an existing, better-targeted UX and
  // would move the failure from "a clear pre-flight warning naming the fix"
  // to "SSH exec silently has no upstream auth and every git-over-SSH
  // operation fails opaquely mid-session". Matches `buildSecretBindings`'s
  // own established philosophy (`src/vm/egress.ts`): config-driven, no
  // silent fallback to a different value, but this module doesn't try to
  // re-do a health check that already exists elsewhere.
  if (git["ssh-agent"] && env.SSH_AUTH_SOCK) {
    options.agent = env.SSH_AUTH_SOCK;
  }

  // `knownHostsFile` is deliberately left unset here, diverging from the
  // plan's §5.2 sketch (which set it to
  // `path.join(os.homedir(), ".ssh/known_hosts")`). Verified against
  // `node_modules/@earendil-works/gondolin/dist/src/qemu/ssh.js`
  // (`createQemuSshInternals`): when `hostVerifier` is not set and either
  // `agent` or `credentials` is present, the SDK already builds a default
  // OpenSSH known_hosts verifier itself via
  // `createOpenSshKnownHostsHostVerifier(normalizeSshKnownHostsFiles(options?.knownHostsFile))`.
  // Reading `normalizeSshKnownHostsFiles`
  // (`.../dist/src/ssh/utils.js`) shows that when `knownHostsFile` is
  // `undefined`, the SDK's own default is *two* files —
  // `path.join(os.homedir(), ".ssh", "known_hosts")` **and**
  // `/etc/ssh/ssh_known_hosts` — not just the user's own file. Explicitly
  // setting `knownHostsFile` to only the user's `~/.ssh/known_hosts`, as
  // the sketch proposed, would *narrow* host-key verification relative to
  // the SDK's own default (dropping the system-wide
  // `/etc/ssh/ssh_known_hosts` entirely) rather than merely restating it —
  // a strictly worse outcome for no benefit, so this function leaves the
  // field unset and lets the SDK apply its own (broader, and now verified
  // correct) default.

  return options;
}
