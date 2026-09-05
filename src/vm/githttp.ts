// `src/vm/githttp.ts` — closes the git-over-HTTPS gap `ssh.execPolicy`
// (`src/vm/gitssh.ts`) already closes for git-over-SSH: fetch/clone needs the
// repo in `git.allow-repos`, push additionally needs `git.allow-push = true`.
// Without this module, an operator whose `[egress] allow` list happens to
// include a git-hosting host (so HTTPS clone/fetch works at all) got no
// corresponding restriction on `git push` over HTTPS to that same host — the
// HTTP transport had no equivalent to `gitssh.ts`'s own SSH-side gate at all.
// This is a later, separate hardening item, not part of the original
// milestone plan `gitssh.ts`/`github.ts` were built under — no milestone tag
// is invented for it here; the mechanism is referenced directly instead.
//
// Structured like `src/policy/github.ts`'s own `githubApiGate`: an
// `onRequest`-shaped HTTP gate (`createHttpHooks({ onRequest })`,
// `docs/gondolin-notes.md` §4) that is purely method/path-shaped — it never
// reads a request body. Lives under `src/vm/`, not `src/policy/` (unlike
// `github.ts`), because it directly reuses `src/vm/gitssh.ts`'s own
// `normalizeRepo`/`matchAnyGlob`/`GIT_UPLOAD_PACK`/`GIT_RECEIVE_PACK` — the
// same canonicalization and allowlist logic the SSH-side gate already uses —
// rather than re-deriving a second, parallel copy of that logic under
// `src/policy/`.
//
// The `${method} ${hostname}${pathname}` audit-subject format matches
// `safeSubject()` (`src/vm/egress.ts`) byte for byte but is reimplemented
// inline below, for the same reason `githubApiGate` does: `buildEgressConfig`
// (`src/vm/egress.ts`) is what wires this module's `gitHttpGate()` into
// `createHttpHooks({ onRequest })`, so a dependency in the other direction
// would be circular.
//
// A git URL path's trailing `.git` is optional, not mandatory — confirmed
// empirically against real github.com via `GIT_CURL_VERBOSE=1 git
// ls-remote`: `git ls-remote https://github.com/octocat/Hello-World` (no
// `.git` typed) sends `GET /octocat/Hello-World/info/refs?service=git-upload-pack`,
// while the same command with `.git` typed sends the identical request shape
// with `.git` in the path instead. git's client uses the configured remote
// URL exactly as given as the path prefix — it never normalizes in either
// direction — and both forms are common (`git remote add origin
// https://github.com/owner/repo`, no `.git`, is extremely common). The
// identical URL-construction path is used for both `git-upload-pack` (fetch)
// and `git-receive-pack` (push) service values, so this applies uniformly to
// both. `parseGitHttpRequest` below therefore captures the raw repo path
// segment as-is (whether or not it happens to end in `.git`) and hands the
// whole raw segment to `normalizeRepo` (`./gitssh.ts`), which already strips
// an optional trailing `.git` as part of its own, already-correct,
// already-tested canonicalization — rather than trying to encode "optional
// `.git`" inside this module's own path-matching regex, where a naive
// `(?:\.git)?` next to a greedy `[^/]+` repo-segment capture would be
// ambiguous/buggy (greedy backtracking can swallow the literal `.git` into
// the capture group incorrectly).
//
// Deliberately scoped to GitHub-shaped repo paths only — exactly two path
// segments (owner, repo) before a recognized suffix — the same "best-effort,
// not exhaustive" limitation `guest/internal/gate/collect.go`'s
// `collectPushRange` already documents for its own refspec gap: a deeper,
// GitLab/self-hosted-style nested path (`/group/subgroup/repo/...`) is not
// recognized by `parseGitHttpRequest` at all, so this gate has no opinion
// about such a request — an accepted, documented gap, not a bypass of
// anything this gate claims to cover.
import { GIT_RECEIVE_PACK, GIT_UPLOAD_PACK, matchAnyGlob, normalizeRepo, RepoTraversalError } from "./gitssh.ts";
import { decodeToFixpoint } from "../policy/github.ts";
import type { EffectiveGitConfig } from "../config/load.ts";
import type { AuditWriter } from "../policy/audit.ts";

/**
 * One recognized git-smart-HTTP path shape: `GET /<owner>/<repo>/info/refs`
 * (ref discovery), `POST /<owner>/<repo>/git-upload-pack` (fetch/clone data
 * transfer), or `POST /<owner>/<repo>/git-receive-pack` (push data
 * transfer). `kind` reuses `src/vm/gitssh.ts`'s own `GIT_UPLOAD_PACK`/
 * `GIT_RECEIVE_PACK` string values for the latter two cases — not new, ad hoc
 * string literals — so a caller comparing `kind` against those constants
 * never has two differently spelled vocabularies to keep in sync.
 */
export interface GitHttpRequestInfo {
  /**
   * Raw `"owner/repo"` or `"owner/repo.git"`, exactly as extracted from the
   * request path — NOT yet run through `normalizeRepo`. `gitHttpGate` is
   * responsible for normalizing before comparing against `git.allow-repos`.
   */
  repo: string;
  kind: "discovery" | typeof GIT_UPLOAD_PACK | typeof GIT_RECEIVE_PACK;
}

// Exactly two path segments (owner, repo-with-optional-`.git`) before a
// recognized suffix. The repo segment is captured as-is via `[^/]+` — no
// attempt is made to strip an optional trailing `.git` here; see the module
// comment for why that job belongs to `normalizeRepo` alone, not this regex.
const GIT_HTTP_PATH_RE = /^\/([^/]+)\/([^/]+)\/(info\/refs|git-upload-pack|git-receive-pack)$/;

/**
 * Pure path-shape parser: recognizes exactly the three git-smart-HTTP path
 * shapes named on `GitHttpRequestInfo`'s own doc comment, requiring exactly
 * two path segments before the suffix. No I/O, and no percent-decoding of its
 * own — `pathname` must already be decoded by the caller (`gitHttpGate`
 * decodes to a fixpoint via `decodeToFixpoint` before ever calling this).
 *
 * Returns `undefined` for anything that isn't shaped like git-smart-HTTP at
 * all: the wrong method for an otherwise-matching path shape (e.g. `POST
 * .../info/refs`, `GET .../git-upload-pack`), a path with more or fewer than
 * two segments before the suffix (so a GitLab/self-hosted-style nested path
 * like `/group/subgroup/repo/git-upload-pack` is deliberately not
 * recognized — see the module comment), an unrecognized suffix entirely, or
 * any other path at the same host. This is a deliberately *narrow* gate, not
 * a general path-allowlist for the whole host — `undefined` here means "this
 * gate has no opinion about this request", not "deny"; see `gitHttpGate`'s
 * own doc comment, step 5.
 *
 * The query string (e.g. `?service=...` on a discovery request) is never
 * read or decoded here, or anywhere in this module: discovery is repo-scoped
 * but never push-scoped (a hostile guest is never obliged to call discovery
 * before POSTing straight to `git-receive-pack`, so there is nothing to gain
 * by parsing `?service=`), and a query-string value doesn't have the same
 * fixpoint-decode story a pathname does (`decodeToFixpoint`'s own doc
 * comment, `src/policy/github.ts`) — a real, unsolved sub-problem this module
 * deliberately does not attempt to solve. `URL.pathname` never includes the
 * query string in the first place, so callers passing it through here get
 * this for free.
 */
export function parseGitHttpRequest(method: string, pathname: string): GitHttpRequestInfo | undefined {
  const match = GIT_HTTP_PATH_RE.exec(pathname);
  if (!match) {
    return undefined;
  }
  const [, owner, repoSegment, suffix] = match;
  const repo = `${owner}/${repoSegment}`;

  if (suffix === "info/refs") {
    return method === "GET" ? { repo, kind: "discovery" } : undefined;
  }
  if (suffix === GIT_UPLOAD_PACK) {
    return method === "POST" ? { repo, kind: GIT_UPLOAD_PACK } : undefined;
  }
  // The only remaining alternative `GIT_HTTP_PATH_RE` can have matched.
  return method === "POST" ? { repo, kind: GIT_RECEIVE_PACK } : undefined;
}

// 403, matching `src/policy/github.ts`'s own `denyResponse` convention (and,
// through it, Gondolin's own default for a hostname-allowlist denial). Plain
// text, no headers or URL/method/repo echoed back from the request that
// triggered it — only the fixed rule-name string this gate itself chose, same
// discipline as `github.ts`'s own version. Not imported/shared with it —
// `github.ts`'s own `denyResponse` is private (not exported), by design, same
// reasoning as that file's own private `pathGlobToRegExp`.
function denyResponse(reason: string): Response {
  return new Response(`corb: request denied by git-http policy — ${reason}\n`, {
    status: 403,
    headers: { "content-type": "text/plain" },
  });
}

/**
 * Builds the `onRequest` hook (`createHttpHooks({ onRequest })`,
 * `docs/gondolin-notes.md` §4) that enforces `git.allow-repos`/
 * `git.allow-push` against git's smart-HTTP protocol — the HTTPS-side
 * counterpart to `src/vm/gitssh.ts`'s `execPolicy`. Structured like
 * `githubApiGate` (`src/policy/github.ts`) function-for-function.
 *
 * Semantics, evaluated in order:
 *   1. `git["allow-hosts"]` undefined or empty means this gate has nothing to
 *      say — return `undefined` immediately, before even constructing a
 *      `URL`. This is the *opposite* asymmetry from `gitssh.ts`'s own
 *      `allowedHosts` (there, an empty array disables the whole SSH
 *      transport entirely — see `buildGitSshOptions`'s own doc comment,
 *      citing the SDK's `createQemuSshInternals`). That doesn't transfer
 *      here: HTTPS git access is already gated by the wholly separate
 *      `egress.allow` mechanism, so "no `git.allow-hosts` configured" for
 *      *this* gate must mean "pass through, I have no opinion" — never
 *      "block all HTTPS git access nobody asked to restrict". Getting this
 *      backwards would be the single most important mistake to make in this
 *      file.
 *   2. If the request's hostname is not in `git["allow-hosts"]`, pass
 *      through untouched — same as `githubApiGate`'s own host-scoping.
 *   3. `subject` is computed once, immediately after the host match, from
 *      the *raw* (not percent-decoded) pathname: exactly `safeSubject()`'s
 *      format (`src/vm/egress.ts`), reimplemented inline for the same reason
 *      `githubApiGate` does (avoiding a circular import — see the module
 *      comment). Every `audit.record` call below reuses this same value,
 *      regardless of which check ends up firing.
 *   4. The pathname is percent-decoded to a fixpoint via `decodeToFixpoint`
 *      (`src/policy/github.ts`). A thrown decode error (a malformed
 *      percent-escape) denies with reason `"malformed percent-encoding in
 *      request path"` — verbatim, matching `githubApiGate`'s own string.
 *      This runs before the path is even checked for being git-shaped at
 *      all: any malformed percent-escape anywhere in the path of a request
 *      to an allow-hosted git host is ambiguous input this gate does not
 *      give the benefit of the doubt, matching `docs/adr/0005`'s
 *      allowlist-never-blocklist posture.
 *   5. `parseGitHttpRequest` is called against the decoded pathname. An
 *      `undefined` result passes through untouched, with no audit event —
 *      this is the "narrow gate, not a general host path-allowlist" boundary
 *      `parseGitHttpRequest`'s own doc comment describes; it is not this
 *      gate's concern.
 *   6. `normalizeRepo(info.repo)` (`./gitssh.ts`) runs in a try/catch. Unlike
 *      `gitssh.ts`'s own SSH case (where the equivalent throw is provably
 *      unreachable, because `getInfoFromSshExecRequest` already rejects `..`
 *      upstream before `execPolicy` ever runs), this branch is genuinely
 *      reachable here: `parseGitHttpRequest`'s regex has no upstream filter
 *      rejecting `..`, so a decoded path whose repo segment contains `..`
 *      really does reach this throw. On catch, denies with the thrown
 *      `RepoTraversalError`'s own `.message` as `reason` — same pattern
 *      `gitssh.ts`'s own `execPolicy` uses for its own, unreachable-in-
 *      practice version of this same check.
 *   7. `matchAnyGlob(git["allow-repos"], repo)` — a `false` result denies
 *      with reason `` `corb git: repository '${info.repo}' is not in
 *      git.allow-repos.` `` (matching `gitssh.ts`'s own exact wording,
 *      substituting the *raw* `info.repo`, not the normalized form, exactly
 *      as `gitssh.ts`'s `execPolicy` does for its own analogous message).
 *   8. `info.kind === GIT_RECEIVE_PACK && !git["allow-push"]` denies with
 *      reason `"corb git: push is disabled for this session (set
 *      git.allow-push = true in config.toml to enable it)."` — verbatim,
 *      matching `gitssh.ts`'s exact wording. Discovery (`"discovery"`) and
 *      fetch (`GIT_UPLOAD_PACK`) are never subject to this check — repo-
 *      scoped, but never push-scoped, per `parseGitHttpRequest`'s own
 *      "discovery never reads `?service=`" design.
 *   9. Otherwise pass through (`undefined`) — allowed. `buildEgressConfig`'s
 *      existing generic `onResponse` handler (`src/vm/egress.ts`) already
 *      records the eventual real `"allow"` once the request round-trips;
 *      recording an early allow here would double-count it — matches
 *      `githubApiGate`'s own convention, and is why this function never
 *      needs its own `onResponse` wiring.
 *
 * Every deny: `channel: "http"` (an HTTP-transport gate, like
 * `githubApiGate` — not `channel: "ssh"`, that's `gitssh.ts`'s own unrelated
 * channel), `decision: "deny"`, the `subject` from step 3, `reason`,
 * `sessionId`. A pass-through never calls `audit.record` at all, at any
 * step — matches `githubApiGate`'s own "pass-through never calls
 * audit.record" convention.
 */
export function gitHttpGate(
  git: EffectiveGitConfig,
  audit: AuditWriter,
  sessionId: string,
): (req: Request) => Response | undefined {
  return (req: Request): Response | undefined => {
    const allowHosts = git["allow-hosts"];
    if (allowHosts === undefined || allowHosts.length === 0) {
      return undefined;
    }

    const url = new URL(req.url);
    if (!allowHosts.includes(url.hostname)) {
      return undefined;
    }

    // Matches `safeSubject()`'s exact format (`src/vm/egress.ts`) — see the
    // module comment for why this is reimplemented rather than imported.
    const subject = `${req.method} ${url.hostname}${url.pathname}`;

    let decodedPathname: string;
    try {
      decodedPathname = decodeToFixpoint(url.pathname);
    } catch {
      const reason = "malformed percent-encoding in request path";
      audit.record({ channel: "http", decision: "deny", subject, reason, sessionId });
      return denyResponse(reason);
    }

    const info = parseGitHttpRequest(req.method, decodedPathname);
    if (info === undefined) {
      return undefined;
    }

    let repo: string;
    try {
      repo = normalizeRepo(info.repo);
    } catch (err) {
      // Genuinely reachable here, unlike gitssh.ts's own equivalent branch —
      // see this function's own doc comment, step 6.
      const reason = err instanceof RepoTraversalError ? err.message : String(err);
      audit.record({ channel: "http", decision: "deny", subject, reason, sessionId });
      return denyResponse(reason);
    }

    if (!matchAnyGlob(git["allow-repos"], repo)) {
      const reason = `corb git: repository '${info.repo}' is not in git.allow-repos.`;
      audit.record({ channel: "http", decision: "deny", subject, reason, sessionId });
      return denyResponse(reason);
    }

    if (info.kind === GIT_RECEIVE_PACK && !git["allow-push"]) {
      const reason =
        "corb git: push is disabled for this session (set git.allow-push = true in config.toml to enable it).";
      audit.record({ channel: "http", decision: "deny", subject, reason, sessionId });
      return denyResponse(reason);
    }

    return undefined;
  };
}
