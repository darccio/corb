// `src/vm/egress.ts` — M3.2 builds the secrets-binding piece of what will
// become the module that assembles `createHttpHooks()`'s full argument
// object. This item exports exactly one pure function, `buildSecretBindings`,
// which turns `EffectiveConfig.secrets` (src/config/load.ts) plus the host
// process environment into the plain `secrets` map shape
// `createHttpHooks({ secrets })` expects (docs/gondolin-notes.md §5):
// `Record<string, { hosts: string[], value: string }>`. The guest only ever
// sees a placeholder that Gondolin itself mints and substitutes on the wire;
// this module's `value` is the *real* secret value, read here from
// `process.env` (or an injected env object) and handed to Gondolin, which
// does the actual placeholder substitution — this module never does that
// substitution itself and never writes the real value anywhere else.
//
// No built-in fallback for `ANTHROPIC_API_KEY` or any other secret name:
// `EffectiveConfig.secrets` is the sole source of truth. `undefined` or `{}`
// is a valid, unremarkable result — zero secrets bound, not an error and not
// a default. Every secret name is handled identically; nothing in this file
// special-cases any particular name.
//
// M3.3 adds `buildEgressConfig()` below, which composes `buildSecretBindings`
// with the rest of `EffectiveConfig.egress` into one `createHttpHooks()`
// call — the allowlist/audit-hook wiring the M3.2 comment above deferred to
// this item. Wiring this function's output into `src/vm/session.ts`
// (replacing that module's current hardcoded `requireApiKey`/
// `MissingApiKeyError`/`ANTHROPIC_HOST` single-secret `createHttpHooks()`
// call) is still M3.4's job, not this one's — nothing here is called from
// `session.ts` or `VM.create()` yet.
import { createHttpHooks, type HttpHooks } from "@earendil-works/gondolin";
import type { DirConfig, EffectiveEgressConfig, EffectivePolicyConfig } from "../config/load.ts";
import type { PartialSecretConfig } from "../config/schema.ts";
import type { AuditWriter } from "../policy/audit.ts";
import { githubApiGate } from "../policy/github.ts";
import { POLICY_HOST, sentinel } from "../policy/sentinel.ts";

/** The real secret value plus the hosts Gondolin is allowed to send it to. Matches `createHttpHooks({ secrets })`'s per-entry shape (docs/gondolin-notes.md §5). */
export interface SecretBinding {
  hosts: string[];
  value: string;
}

/**
 * Thrown when a `[secrets.NAME]` block has no usable `hosts` list. A secret's
 * blast radius is exactly the hosts it's bound to (docs/gondolin-notes.md
 * §4/§5), so a secret with nowhere it's allowed to reach is a misconfigured,
 * dead binding rather than something to silently drop or silently allow
 * everywhere — this fails loudly instead.
 */
export class SecretHostsMissingError extends Error {
  constructor(name: string) {
    super(
      `corb egress: [secrets.${name}] has no 'hosts' — a secret must specify which host(s) it may be sent to.\n` +
        `  Add hosts = ["example.com"] (or similar) to [secrets.${name}] in config.toml.`,
    );
    this.name = "SecretHostsMissingError";
  }
}

/**
 * Thrown when a non-`optional` secret's env var is unset (or empty) at bind
 * time. Generalizes `src/vm/session.ts`'s `MissingApiKeyError` (M1.6) to an
 * arbitrary secret name rather than hardcoding `ANTHROPIC_API_KEY`.
 */
export class MissingSecretError extends Error {
  constructor(name: string) {
    super(
      `corb egress: required secret '${name}' is not set in the host environment.\n` +
        `  Set it before running corb, e.g. \`${name}=... corb run\`, ` +
        `or mark it optional = true in [secrets.${name}] in config.toml if that's acceptable for this workspace.`,
    );
    this.name = "MissingSecretError";
  }
}

/**
 * Turns `EffectiveConfig.secrets` plus the host process environment into the
 * plain `secrets` object `createHttpHooks({ secrets })` expects. Pure: no I/O
 * beyond reading the `env` object it's handed, no side effects, nothing
 * written anywhere but the returned map.
 *
 * `secrets` being `undefined` or `{}` is not an error — it is the correct,
 * valid "zero secrets bound" result. Do not add a fallback here for any
 * particular secret name; `EffectiveConfig.secrets` is the sole input.
 */
export function buildSecretBindings(
  secrets: Record<string, PartialSecretConfig> | undefined,
  env: NodeJS.ProcessEnv,
): Record<string, SecretBinding> {
  const result: Record<string, SecretBinding> = {};
  if (secrets === undefined) {
    return result;
  }

  for (const [name, config] of Object.entries(secrets)) {
    if (config.hosts === undefined || config.hosts.length === 0) {
      throw new SecretHostsMissingError(name);
    }

    // An empty-string env var (`FOO=` in a shell) is treated the same as
    // unset: it is almost always a mistake, not an intentionally empty
    // secret, and binding an empty string as a "real" value would be
    // actively misleading.
    const value = env[name];
    if (value === undefined || value === "") {
      if (config.optional === true) {
        continue;
      }
      throw new MissingSecretError(name);
    }

    result[name] = { hosts: config.hosts, value };
  }

  return result;
}

/**
 * Builds the audit-log `subject` string for one HTTP request/response pair:
 * exactly `` `${method} ${hostname}${pathname}` ``, per `docs/design.md` §6
 * ("Never log request URLs or headers from an HTTP hook. Secrets may already
 * be expanded at that point. Log the hostname, the method, and the
 * decision.") and `docs/gondolin-notes.md` §4's matching sharp edge. `req.url`
 * is parsed only to pull `hostname`/`pathname` back out of it — the query
 * string and every header are never read here, on purpose: a secret placed
 * in a query string is only *usually* safe from substitution (`createHttpHooks`
 * defaults `replaceSecretsInQuery` to `false`, and this module never sets it
 * to `true`), and a header can carry anything a caller put there, so both are
 * excluded from the audit trail entirely rather than trusted to not contain
 * one.
 */
export function safeSubject(req: Request): string {
  const url = new URL(req.url);
  return `${req.method} ${url.hostname}${url.pathname}`;
}

/**
 * What a caller needs to finish booting a session's network egress. Mirrors
 * `createHttpHooks()`'s own result shape for `httpHooks`/`env`, plus
 * `allowWebSockets` folded in from `EffectiveEgressConfig.websockets` for
 * convenience — see the field's own doc comment for why that one is never
 * passed to `createHttpHooks()` itself.
 */
export interface EgressConfig {
  /** Pass straight through to `VM.create({ httpHooks })`. */
  httpHooks: HttpHooks;
  /** The placeholder env `createHttpHooks()` minted for the bound secrets; spread into the guest environment. */
  env: Record<string, string>;
  /**
   * NOT a `createHttpHooks()` option, despite living next to `allowedHosts`/
   * `blockInternalRanges` conceptually — confirmed against the shipped
   * `VMOptions` type (`node_modules/@earendil-works/gondolin/dist/src/vm/types.d.ts`):
   * `allowWebSockets?: boolean` is a `VM.create()` option, while
   * `CreateHttpHooksOptions` (`.../dist/src/http/hooks.d.ts`) has no such
   * field at all. This is `EffectiveEgressConfig.websockets`'s value,
   * returned as a plain field for the caller (M3.4) to thread into its own,
   * separate `VM.create({ allowWebSockets })` call.
   */
  allowWebSockets: boolean;
}

/**
 * One `createHttpHooks({ onRequest })`-shaped hook: `undefined` means
 * "pass through, I have no opinion about this request"; a `Response` means
 * "fully handled, short-circuit". Matches both `sentinel()`'s (async) and
 * `githubApiGate()`'s (sync, but its return value is still awaitable) own
 * signatures.
 */
type OnRequestHook = (req: Request) => Promise<Response | undefined> | Response | undefined;

/**
 * Composes several `onRequest` hooks into the single one `createHttpHooks()`
 * accepts: tries each hook in `hooks` order, `await`-ing its result, and
 * returns the first non-`undefined` `Response` — or `undefined` once every
 * hook has passed through. `createHttpHooks()` takes exactly one `onRequest`,
 * not a list (per the forward pointer this replaces, previously at this
 * file's `buildEgressConfig` doc comment), so this is the composition
 * mechanism that pointer was waiting for.
 *
 * Order is `sentinel` before `githubApiGate` at this function's own call
 * site below, matching the plan's own `composeOnRequest([sentinel(...),
 * githubApiGate(...)])` text — but this is for readability, not because
 * order is load-bearing: neither hook's behavior actually depends on running
 * before or after the other, since each scopes itself to a completely
 * disjoint hostname (`POLICY_HOST` vs. `api.github.com`) before doing
 * anything else.
 */
export function composeOnRequest(hooks: readonly OnRequestHook[]): OnRequestHook {
  return async (req: Request): Promise<Response | undefined> => {
    for (const hook of hooks) {
      const result = await hook(req);
      if (result !== undefined) {
        return result;
      }
    }
    return undefined;
  };
}

/**
 * Structurally equivalent to "policy content-checks are off" — the default
 * `policy` value `buildEgressConfig` uses when a caller omits it entirely.
 * Matches `sentinel()`'s own step 1 (`policy.enabled === false` -> pass
 * through untouched), so an omitted `policy` costs nothing for any existing
 * call site that has no opinion about it. `"fail-open": true` mirrors
 * `src/config/load.ts`'s own built-in default for the same field.
 */
const INERT_POLICY: EffectivePolicyConfig = { enabled: false, "secret-scan": false, "fail-open": true };

/**
 * Composes `buildSecretBindings` with the rest of `egress` into one
 * `createHttpHooks()` call, wires its `onResponse` hook to the unified audit
 * log (`src/policy/audit.ts`, M3.1), and wires its `onRequest` hook to
 * `composeOnRequest([sentinel(...), githubApiGate(...)])` — M7.2's
 * out-of-guest content-check sentinel (`src/policy/sentinel.ts`,
 * `policy.corb.invalid`, `docs/design.md` §5) ahead of the GitHub API
 * method/path gate (`egress.github-api`, `src/policy/github.ts`, M4.2) — the
 * mechanism that makes `gh api -X DELETE` refusable. Both hooks are
 * themselves complete no-ops whenever their own config is inert
 * (`policy.enabled === false`; `egress["github-api"]` `undefined`), so this
 * wiring costs nothing for a workspace that doesn't use either.
 *
 * `policy` and `dirs` are optional, each defaulting to inert/disabled
 * behavior when omitted (`INERT_POLICY`; `dirs` to `[]`) — this keeps every
 * existing caller of this function (this module's own unit tests and the
 * `.e2e.ts` suites, none of which care about the content-check sentinel)
 * compiling and behaving exactly as before with no edits to them. Real
 * callers (`src/vm/session.ts`) always pass both explicitly.
 *
 * Still deliberately passes neither `isRequestAllowed` nor `isIpAllowed`:
 * nothing in scope for this codebase needs them yet.
 *
 * Also registers every bound secret's real value with `audit` via
 * `addRedactedSecrets()` before doing anything else with it, so the audit
 * log's defense-in-depth redaction pass (`src/policy/audit.ts`, M3.1) —
 * previously built but never fed any values, since the real secret values
 * don't exist yet at `createAuditWriter()`'s own call site
 * (`src/commands/run.ts`) — actually has something to scrub for the rest of
 * this session, on top of the primary mechanism (`safeSubject()` below never
 * constructing an unsafe `subject`/`reason` in the first place).
 *
 * `onResponse` is the only hook this item wires up, and only the "allow"
 * case is observable through it. Read against the installed SDK's own
 * `createHttpHooks()` implementation
 * (`node_modules/@earendil-works/gondolin/dist/src/http/hooks.js`): a
 * hostname-allowlist denial happens inside the *internal* `isIpAllowed`
 * this function wires up itself (`matchesAnyHost(info.hostname, allowedHosts)`
 * returning false before ever calling a caller-supplied `isIpAllowed`), and
 * `httpHooks.onResponse` is set to exactly `options.onResponse` with no
 * wrapping — it is invoked by Gondolin's own qemu/http layer only once a
 * request has actually round-tripped to an allowed upstream. There is no
 * hook this item can wire that fires for a bare `allowedHosts` denial; only
 * a caller-supplied `isRequestAllowed`/`isIpAllowed` (out of scope here)
 * would ever see that decision. So `onResponse` only ever needs to record
 * `"allow"`.
 *
 * `POLICY_HOST` (`src/policy/sentinel.ts`) is added to `allowedHosts`
 * unconditionally, per `docs/design.md` §5 ("The hostname is added to
 * allowedHosts so it is not dropped before the hook sees it"). Not strictly
 * load-bearing for `sentinel()` to intercept and handle a request —
 * `createHttpHooks()`'s internal `onRequest` wrapper runs `options.onRequest`
 * *before* the `allowedHosts` check, and a returned `Response` short-circuits
 * before that check is ever reached (`docs/gondolin-notes.md` §4; already
 * empirically confirmed by M4.4's own `githubApiGate` e2e suite, which works
 * without `api.github.com` in `egress.allow` for the identical reason) — but
 * it is cheap, harmless, explicitly called for by the design doc, and is
 * defense-in-depth for the case where `sentinel()` itself is bypassed or
 * misconfigured (e.g. `policy.enabled=false`): without it, a guest process
 * reaching for `policy.corb.invalid` would otherwise hit the `allowedHosts`
 * gate and fail there, in an equally inert way, rather than the request
 * having any chance of behaving unexpectedly.
 */
export function buildEgressConfig(
  egress: EffectiveEgressConfig,
  secrets: Record<string, PartialSecretConfig> | undefined,
  env: NodeJS.ProcessEnv,
  audit: AuditWriter,
  sessionId: string,
  policy: EffectivePolicyConfig = INERT_POLICY,
  dirs: readonly DirConfig[] = [],
): EgressConfig {
  const secretBindings = buildSecretBindings(secrets, env);
  audit.addRedactedSecrets(Object.values(secretBindings).map((binding) => binding.value));

  // `allowedHosts` sentinels are asymmetric (docs/gondolin-notes.md §4):
  // omitting the field to createHttpHooks() means "allow all"; an explicit
  // `[]` means "deny all". `EffectiveEgressConfig.allow` being
  // `string[] | undefined` represents "no `egress.allow` configured at all"
  // with `undefined`, and that must become "deny all" here — never "omit the
  // field, allow everything". `?? []` is therefore load-bearing, not a
  // stylistic default; do not change this to pass `egress.allow` through
  // unmodified. `POLICY_HOST` is always appended — see this function's own
  // doc comment for why.
  const allowedHosts = [...(egress.allow ?? []), POLICY_HOST];
  const allowedInternalHosts = egress["allow-internal"] ?? [];

  const { httpHooks, env: secretEnv } = createHttpHooks({
    allowedHosts,
    allowedInternalHosts,
    blockInternalRanges: egress["block-internal-ranges"],
    secrets: secretBindings,
    onRequest: composeOnRequest([
      sentinel(policy, dirs, audit, sessionId),
      githubApiGate(egress["github-api"], audit, sessionId),
    ]),
    onResponse: (res, req) => {
      audit.record({
        channel: "http",
        decision: "allow",
        subject: safeSubject(req),
        reason: String(res.status),
        sessionId,
      });
    },
  });

  return {
    httpHooks,
    env: secretEnv,
    allowWebSockets: egress.websockets,
  };
}
