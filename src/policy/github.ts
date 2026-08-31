// `src/policy/github.ts` — M4.2 builds the `[egress.github-api]` HTTP
// method/path allowlist gate: the mechanism that makes `gh api -X DELETE`
// refusable. This is an `onRequest` short-circuit
// (`createHttpHooks({ onRequest })`, `docs/gondolin-notes.md` §4) — the same
// mechanism `docs/design.md` §5 describes for the (separate, M7-owned)
// content-check sentinel — but this gate is purely method/path-shaped: it
// never reads a request body, never calls `req.json()`, and is entirely this
// milestone's own, unrelated to M7's sentinel-host handler.
//
// Deliberately lives under `src/policy/`, not `src/vm/`, mirroring
// `src/policy/audit.ts`'s own layering. This module has, and must keep, zero
// dependency on `src/vm/egress.ts`: `buildEgressConfig()` there is what wires
// `githubApiGate()`'s return value into `createHttpHooks({ onRequest })`, so
// a dependency in the other direction would be circular (`vm/egress.ts` ->
// `policy/github.ts` -> `vm/egress.ts`). That is why the
// `${method} ${hostname}${pathname}` audit-subject format matches
// `safeSubject()` (`src/vm/egress.ts`) byte for byte but is reimplemented
// inline below rather than imported.
import type { PartialEgressGithubApiConfig } from "../config/schema.ts";
import type { AuditWriter } from "./audit.ts";

/**
 * `[egress.github-api]`'s target host when the block is present but `hosts`
 * is not spelled out inside it. Never consulted when the whole
 * `[egress.github-api]` table is absent — see `githubApiGate`'s doc comment,
 * point 1. This default deliberately does NOT live in
 * `src/config/load.ts`'s `BUILTIN_DEFAULTS`: "the block is present but
 * `hosts` wasn't spelled out" defaults sensibly; "the block is entirely
 * absent" does not synthesize one (`BUILTIN_DEFAULTS` must never gain a
 * `github-api` entry at all).
 */
const DEFAULT_GITHUB_API_HOST = "api.github.com";

// Deliberately minimal, scoped to exactly what `docs/design.md`'s own
// `deny-paths` examples need (`"**/actions/secrets/**"`,
// `"**/actions/variables/**"`, `"/user/keys**"`): `**` matches across `/`
// (including zero characters); everything else is a literal. This is not
// `src/vfs/glob.ts`'s future general VFS glob engine (M5's job — that
// directory doesn't exist yet, confirmed by `find src/vfs` coming up empty)
// and it is not `src/vm/gitssh.ts`'s private `globToRegExp` either — that one
// is deliberately single-path-segment `*`-only, scoped to repo-name matching
// against `git.allow-repos`, a different alphabet of patterns entirely, and
// is not imported or reused here. Building either of those here would be
// scope creep for a three-pattern path blocklist.
function pathGlobToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .split("**")
    .map((segment) => segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`);
}

// `URL.pathname` never percent-decodes — `"%73ecrets"` stays exactly that,
// not `"secrets"` — so matching `deny-paths` against the raw pathname alone
// misses `GET /repos/o/r/actions/%73ecrets/FOO`: GitHub itself decodes
// during routing and serves the real `.../actions/secrets/...` endpoint,
// so the pattern `"**/actions/secrets/**"` never fires. Decoding is
// repeated to a fixpoint (capped at `MAX_DECODE_ITERATIONS`, so a
// pathological input cannot spin this forever) so a *double*-encoded
// segment (`%2573` -> `%73` -> `s`) is also caught, not just a single
// decode.
const MAX_DECODE_ITERATIONS = 4;

/** Throws (via `decodeURIComponent`) if `pathname` contains a malformed percent-escape (e.g. a lone `%ZZ`) at any point during the fixpoint iteration — see the caller for why that is treated as a deny, matching `docs/adr/0005`'s allowlist-never-blocklist posture: an ambiguous path must not be given the benefit of the doubt. */
function decodeToFixpoint(pathname: string): string {
  let current = pathname;
  for (let i = 0; i < MAX_DECODE_ITERATIONS; i++) {
    const next = decodeURIComponent(current);
    if (next === current) {
      return current;
    }
    current = next;
  }
  return current;
}

// 403, matching Gondolin's own default for a hostname-allowlist denial
// (`HttpRequestBlockedError`, per `test/e2e/egress.e2e.ts`'s module
// comment). Plain text, no headers or URL echoed back from the request that
// triggered it — only the fixed rule-name string this gate itself chose.
function denyResponse(reason: string): Response {
  return new Response(`corb: request denied by egress.github-api policy — ${reason}\n`, {
    status: 403,
    headers: { "content-type": "text/plain" },
  });
}

/**
 * Builds the `onRequest` hook (`createHttpHooks({ onRequest })`,
 * `docs/gondolin-notes.md` §4) that enforces `[egress.github-api]`'s method
 * allowlist and path blocklist. Synchronous — nothing here needs to read the
 * request body, and this gate never does: only `req.method` and `req.url`
 * are read, and neither is ever logged raw, matching
 * `docs/gondolin-notes.md` §4's caution that secrets may already be expanded
 * by the time `onRequest` runs.
 *
 * Semantics, evaluated in order:
 *   1. `githubApi === undefined` — no `[egress.github-api]` table configured
 *      at all — is a complete no-op: every request passes through
 *      untouched, method/path unrestricted. Matches `buildSecretBindings`
 *      returning `{}` for an unconfigured `[secrets]` block (M3.2):
 *      config-driven only, no built-in fallback that enables a gate the user
 *      never asked for.
 *   2. Otherwise resolve the target host list: `githubApi.hosts ??
 *      ["api.github.com"]`.
 *   3. If the request's hostname is not in that resolved list, this gate has
 *      nothing to say about the request at all — pass through untouched. A
 *      request to, say, `api.anthropic.com` must never be touched by this
 *      gate.
 *   4. Hostname matches: `githubApi.methods`, if set, is an *allowlist*
 *      (`docs/design.md`'s own words: "enforced in onRequest — allowlist,
 *      not blocklist") — a method not in it is denied. Left unset, there is
 *      no method restriction at all; this is the concrete mechanism that
 *      makes `gh api -X DELETE` refusable once a workspace sets
 *      `methods = ["GET", "POST", "PATCH"]` itself. There is no built-in
 *      default method list.
 *   5. `githubApi["deny-paths"]`, if set, is a glob *blocklist* matched
 *      against the pathname — both its raw form and its percent-decoded
 *      form (see `decodeToFixpoint`), since `URL.pathname` never decodes on
 *      its own and GitHub itself does during routing: any matching pattern
 *      denies, regardless of method — even a method the allowlist above
 *      would otherwise have permitted. A pathname containing a malformed
 *      percent-escape is denied outright (fail-closed on ambiguous input)
 *      rather than matched against its raw form only.
 *   6. If neither restriction is configured (the block exists only to set
 *      `hosts`, say), the gate matches the host and denies nothing.
 *
 * A denial returns a synthetic 403 `Response` and records exactly one
 * `channel: "http", decision: "deny"` audit event, named by which rule
 * fired (`"method not allowed"` or `"path denied: <pattern>"`). A
 * pass-through (host doesn't match, or nothing about this request violates a
 * configured restriction) never records anything here: `onResponse`
 * (`buildEgressConfig`, `src/vm/egress.ts`) already records the eventual
 * real `"allow"` once a passed-through request actually completes —
 * recording an early "allow" here would double-count it, or record it
 * before the request has gone anywhere.
 */
export function githubApiGate(
  githubApi: PartialEgressGithubApiConfig | undefined,
  audit: AuditWriter,
  sessionId: string,
): (req: Request) => Response | undefined {
  // Compiled once per gate (i.e. once per session), not once per request:
  // `githubApi["deny-paths"]` is fixed for the lifetime of this closure, so
  // recompiling every pattern's regex on every single request — as an
  // earlier version of this function did, inside the per-request closure
  // below — was wasted work on the hot path of every allowed request too.
  const compiledDenyPaths = githubApi?.["deny-paths"]?.map((pattern) => ({ pattern, regex: pathGlobToRegExp(pattern) }));

  return (req: Request): Response | undefined => {
    if (githubApi === undefined) {
      return undefined;
    }

    const url = new URL(req.url);
    const hosts = githubApi.hosts ?? [DEFAULT_GITHUB_API_HOST];
    if (!hosts.includes(url.hostname)) {
      return undefined;
    }

    // Matches `safeSubject()`'s exact format (`src/vm/egress.ts`) — see the
    // module comment for why this is reimplemented rather than imported.
    const subject = `${req.method} ${url.hostname}${url.pathname}`;

    if (githubApi.methods !== undefined && !githubApi.methods.includes(req.method)) {
      const reason = "method not allowed";
      audit.record({ channel: "http", decision: "deny", subject, reason, sessionId });
      return denyResponse(reason);
    }

    if (compiledDenyPaths !== undefined) {
      let decodedPathname: string;
      try {
        decodedPathname = decodeToFixpoint(url.pathname);
      } catch {
        const reason = "malformed percent-encoding in request path";
        audit.record({ channel: "http", decision: "deny", subject, reason, sessionId });
        return denyResponse(reason);
      }
      for (const { pattern, regex } of compiledDenyPaths) {
        if (regex.test(url.pathname) || regex.test(decodedPathname)) {
          const reason = `path denied: ${pattern}`;
          audit.record({ channel: "http", decision: "deny", subject, reason, sessionId });
          return denyResponse(reason);
        }
      }
    }

    return undefined;
  };
}
