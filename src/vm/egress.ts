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
// Deliberately does not call `createHttpHooks()` and does not import
// anything from `@earendil-works/gondolin` — that, plus `allowedHosts`/
// `allowedInternalHosts`/`blockInternalRanges`/audit-hook wiring onto this
// same file, is M3.3's job. Wiring this function's output into
// `src/vm/session.ts` (replacing that module's current hardcoded
// `requireApiKey`/`MissingApiKeyError` single-secret logic) is M3.4's job.
//
// No built-in fallback for `ANTHROPIC_API_KEY` or any other secret name:
// `EffectiveConfig.secrets` is the sole source of truth. `undefined` or `{}`
// is a valid, unremarkable result — zero secrets bound, not an error and not
// a default. Every secret name is handled identically; nothing in this file
// special-cases any particular name.
import type { PartialSecretConfig } from "../config/schema.ts";

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
