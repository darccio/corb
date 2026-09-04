// `src/config/trust.ts` — M2.3: the trust ratchet's pure decision logic.
// Given the `EffectiveConfig` a workspace was last accepted with (or
// `undefined`, if this is the first time) and the `EffectiveConfig` it has
// now, decide whether the change is safe to proceed on silently ("trusted")
// or must be confirmed by a human ("requires-confirmation"), and provide the
// pure store-update helper for recording a fresh acceptance. Like
// `src/config/schema.ts` (M2.1) and `src/config/load.ts` (M2.2), this module
// does no filesystem I/O (no reading/writing `~/.config/corb/trusted.json`,
// no `os.homedir()`) and no interactive prompting — both are wiring left to
// a later milestone (M2.6) that actually hooks this into `corb run`. Every
// `EffectiveConfig` this module receives is assumed to already be built from
// only the persistent, on-disk layers (built-in defaults + config.toml +
// workspace file) — excluding the CLI-flags layer is the caller's job; this
// module has no CLI-flag awareness at all.
import { createHash } from "node:crypto";
import type { DirConfig, DirRuleConfig, EffectiveConfig } from "./load.ts";
import type { DirMode, PartialSecretConfig } from "./schema.ts";

/**
 * One workspace's accepted-config snapshot, as stored inside
 * `~/.config/corb/trusted.json`. Plain, JSON-serializable data only — no
 * class instances, no methods. `configHash` lets a caller short-circuit "did
 * anything change at all" without running a full diff; `acceptedConfig` is
 * kept in full (not just the hash) because diffing against the *next* run's
 * config needs a structural previous value to compare against, and a hash
 * cannot be un-hashed back into one.
 */
export interface TrustedWorkspaceRecord {
  configHash: string;
  acceptedConfig: EffectiveConfig;
  acceptedAt: number;
}

/**
 * The whole `trusted.json` file: multiple workspaces in one store, keyed by
 * a caller-chosen stable identifier. This module doesn't derive or enforce
 * the key itself — `recordAcceptance` below just takes whatever string the
 * caller passes — but `EffectiveConfig.name` is the natural choice, since
 * that's what identifies a workspace. One consequence worth noting: keying
 * by `name` means renaming a workspace file's `name` field starts a fresh
 * trust history (the old record is simply orphaned under its old key). That
 * is a reasonable, expected consequence of using a human-editable field as
 * the identifier, not a bug this module needs to guard against.
 */
export type TrustStore = Record<string, TrustedWorkspaceRecord>;

export type TrustVerdict = "trusted" | "requires-confirmation";

/**
 * One itemized widening or narrowing change, human-readable so a later
 * milestone (`corb explain`, M2.5) can print it directly. `field` is a
 * dotted/indexed path in the same spirit as `ConfigParseError.location`
 * (`src/config/schema.ts`) — e.g. `"egress.allow"`, `"dir.corb.mode"`,
 * `"secrets.GITHUB_TOKEN.hosts"` — not necessarily unique per change, since
 * e.g. two hosts gained by the same list produce two changes with the same
 * `field`.
 */
export interface ConfigChange {
  field: string;
  description: string;
}

/**
 * The result of comparing a previous accepted `EffectiveConfig` to a current
 * one. `widened`/`narrowed` are itemized so a later milestone can render a
 * full diff, not just the pass/fail verdict — narrowing-only changes are
 * reported here too even though nothing in this milestone consumes them.
 */
export interface TrustEvaluation {
  verdict: TrustVerdict;
  widened: ConfigChange[];
  narrowed: ConfigChange[];
}

// ---------------------------------------------------------------------------
// Canonical JSON + hashing
// ---------------------------------------------------------------------------

// Object key insertion order in JS is not guaranteed to be stable across
// different code paths that might construct structurally-equal-but-
// differently-ordered objects (e.g. two `EffectiveConfig` values built by
// merging layers in different orders that happen to net out the same). Sort
// object keys recursively before hashing so the hash only depends on
// content, never on construction order. Arrays are left in their existing
// order deliberately: order is semantically meaningful for some arrays
// (`dir`) and not others (`egress.allow`), and M2.2's merge already produces
// deterministic array order, so re-sorting arrays here would only add
// complexity for no real benefit. `undefined`-valued keys are dropped so
// `{ a: undefined }` hashes identically to `{}`, matching
// `exactOptionalPropertyTypes`'s own "absent, not present-but-undefined"
// discipline.
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const result: Record<string, unknown> = {};
    for (const [key, v] of entries) {
      result[key] = canonicalize(v);
    }
    return result;
  }
  return value;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(canonicalize(a)) === JSON.stringify(canonicalize(b));
}

/** Pure sha256 hash of `config`'s canonical JSON serialization. See `canonicalize` for what "canonical" means here. */
export function hashEffectiveConfig(config: EffectiveConfig): string {
  return createHash("sha256").update(JSON.stringify(canonicalize(config))).digest("hex");
}

// ---------------------------------------------------------------------------
// The widening/narrowing rule table
// ---------------------------------------------------------------------------

interface RuleResult {
  widened: ConfigChange[];
  narrowed: ConfigChange[];
}

interface Rule {
  field: string;
  evaluate(previous: EffectiveConfig, current: EffectiveConfig): RuleResult;
}

function setAdditions(from: string[] | undefined, to: string[] | undefined): string[] {
  const fromSet = new Set(from ?? []);
  return (to ?? []).filter((item) => !fromSet.has(item));
}

/** A `string[]` field where gaining an entry is widening and losing one is narrowing (`egress.allow`, `git.allow-hosts`, ...). */
function additiveArrayRule(field: string, get: (config: EffectiveConfig) => string[] | undefined): Rule {
  return {
    field,
    evaluate(previous, current) {
      const gained = setAdditions(get(previous), get(current));
      const lost = setAdditions(get(current), get(previous));
      return {
        widened: gained.map((item) => ({ field, description: `${field} gained '${item}'` })),
        narrowed: lost.map((item) => ({ field, description: `${field} lost '${item}'` })),
      };
    },
  };
}

/**
 * A boolean field where moving away from `wideningFrom` is widening and
 * moving back to it is narrowing. E.g. `git.ssh-agent`'s widening direction
 * is `false -> true`, so `wideningFrom` is `false`.
 */
function booleanRule(field: string, get: (config: EffectiveConfig) => boolean, wideningFrom: boolean): Rule {
  return {
    field,
    evaluate(previous, current) {
      const prev = get(previous);
      const curr = get(current);
      if (prev === curr) {
        return { widened: [], narrowed: [] };
      }
      const change: ConfigChange = { field, description: `${field} changed from ${prev} to ${curr}` };
      return prev === wideningFrom ? { widened: [change], narrowed: [] } : { widened: [], narrowed: [change] };
    },
  };
}

function ruleKey(rule: DirRuleConfig): string {
  return `${rule.glob ?? ""} ${rule.mode ?? ""} ${rule.reason ?? ""}`;
}

/**
 * Whether `a` and `b` contain the same ruleKeys the same number of times
 * each, ignoring order. `dirRule` below uses this to choose message wording
 * for a rule-list change that already failed its prefix-safety check: a
 * *pure reorder* (same membership, different sequence) gets its own specific
 * wording, distinct from any other prefix-breaking change (an insertion, or
 * a reorder combined with an add/remove).
 */
function sameRuleKeyMultiset(a: string[], b: string[]): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((key, i) => key === sortedB[i]);
}

const dirRule: Rule = {
  field: "dir",
  evaluate(previous, current): RuleResult {
    const widened: ConfigChange[] = [];
    const narrowed: ConfigChange[] = [];
    const prevByName = new Map(previous.dir.map((d): [string, DirConfig] => [d.name, d]));
    const currByName = new Map(current.dir.map((d): [string, DirConfig] => [d.name, d]));

    for (const name of currByName.keys()) {
      if (!prevByName.has(name)) {
        widened.push({ field: `dir.${name}`, description: `dir '${name}' added` });
      }
    }
    for (const name of prevByName.keys()) {
      if (!currByName.has(name)) {
        narrowed.push({ field: `dir.${name}`, description: `dir '${name}' removed` });
      }
    }

    for (const [name, prevDir] of prevByName) {
      const currDir = currByName.get(name);
      if (currDir === undefined) {
        continue;
      }

      // Absent `mode` means `rw` downstream (`src/commands/run.ts`'s
      // `toWorkspaceDirSpec`, `src/vm/session.ts`'s mount loop) — normalize
      // before comparing, or `"ro" -> undefined` (dropping a `mode = "ro"`
      // line) reads as no change at all and silently widens to rw.
      const prevMode: DirMode = prevDir.mode ?? "rw";
      const currMode: DirMode = currDir.mode ?? "rw";
      if (prevMode === "ro" && currMode === "rw") {
        widened.push({ field: `dir.${name}.mode`, description: `dir '${name}' mode changed from 'ro' to 'rw'` });
      } else if (prevMode === "rw" && currMode === "ro") {
        narrowed.push({ field: `dir.${name}.mode`, description: `dir '${name}' mode changed from 'rw' to 'ro'` });
      }

      const prevRuleKeyList = prevDir.rules.map(ruleKey);
      const currRuleKeyList = currDir.rules.map(ruleKey);
      const currRuleKeys = new Set(currRuleKeyList);
      for (const rule of prevDir.rules) {
        if (!currRuleKeys.has(ruleKey(rule))) {
          widened.push({
            field: `dir.${name}.rules`,
            description: `dir '${name}' lost rule '${rule.glob ?? "?"}' (${rule.mode ?? "?"})`,
          });
        }
      }

      // Enforcement (`src/vfs/policy.ts` / `src/vfs/glob-policy.ts`) walks
      // `rules` first-match-wins, so a rule's *position* is just as
      // security-relevant as its presence. Diffing `rules` as a plain Set for
      // gained entries (as this used to do) misses that inserting a new,
      // broader rule *ahead of* an existing narrower one can shadow the
      // narrower rule at enforcement time while looking like pure narrowing
      // (only an addition, nothing lost) to a membership diff. The one
      // invariant that is actually safe: the previous rule list, in its
      // original order, must remain an untouched *prefix* of the current
      // list.
      //
      //  - A pure append (new rules added only at the very end, everything
      //    before them unchanged) keeps the old list as a prefix of the new
      //    one -> safe; only the genuinely-new tail past the preserved
      //    prefix is reported as narrowing, same wording as a plain gained-
      //    rule diff would use.
      //  - Anything else — a pure reorder (same ruleKeys, same counts,
      //    different sequence), an insertion ahead of/between existing
      //    rules, or a reorder combined with an add/remove — breaks the
      //    prefix at some index before the end, so it is treated as
      //    widening, matching this module's existing bias of failing toward
      //    requiring confirmation whenever it cannot positively rule out a
      //    widening. The pure-reorder sub-case keeps its own, more specific
      //    wording; every other non-safe-prefix change shares a generic one.
      const isSafePrefix =
        currRuleKeyList.length >= prevRuleKeyList.length &&
        prevRuleKeyList.every((key, i) => key === currRuleKeyList[i]);

      if (isSafePrefix) {
        for (const rule of currDir.rules.slice(prevRuleKeyList.length)) {
          narrowed.push({
            field: `dir.${name}.rules`,
            description: `dir '${name}' gained rule '${rule.glob ?? "?"}' (${rule.mode ?? "?"})`,
          });
        }
      } else if (sameRuleKeyMultiset(prevRuleKeyList, currRuleKeyList)) {
        widened.push({
          field: `dir.${name}.rules`,
          description: `dir '${name}' rules reordered (first-match-wins order changed; treated as widening)`,
        });
      } else {
        widened.push({
          field: `dir.${name}.rules`,
          description: `dir '${name}' rules changed in a way that is not a safe append (first-match-wins order may have changed; treated as widening)`,
        });
      }
    }

    return { widened, narrowed };
  },
};

const secretsRule: Rule = {
  field: "secrets",
  evaluate(previous, current): RuleResult {
    const widened: ConfigChange[] = [];
    const narrowed: ConfigChange[] = [];
    const prevSecrets = previous.secrets ?? {};
    const currSecrets = current.secrets ?? {};
    const names = new Set([...Object.keys(prevSecrets), ...Object.keys(currSecrets)]);

    for (const name of names) {
      const prevEntry = prevSecrets[name];
      const currEntry = currSecrets[name];
      if (prevEntry === undefined && currEntry !== undefined) {
        widened.push({ field: `secrets.${name}`, description: `secret '${name}' added` });
        continue;
      }
      if (prevEntry !== undefined && currEntry === undefined) {
        narrowed.push({ field: `secrets.${name}`, description: `secret '${name}' removed` });
        continue;
      }
      if (prevEntry === undefined || currEntry === undefined) {
        continue;
      }
      const gained = setAdditions(prevEntry.hosts, currEntry.hosts);
      const lost = setAdditions(currEntry.hosts, prevEntry.hosts);
      for (const host of gained) {
        widened.push({ field: `secrets.${name}.hosts`, description: `secret '${name}' gained host '${host}'` });
      }
      for (const host of lost) {
        narrowed.push({ field: `secrets.${name}.hosts`, description: `secret '${name}' lost host '${host}'` });
      }
    }

    return { widened, narrowed };
  },
};

/**
 * `policy.max-changed-files` is the one field in the widening table whose
 * direction is not the obvious mirror of "gaining a list entry is
 * widening". Reasoning, worked through explicitly rather than pattern-
 * matched from the additive-array rules above:
 *
 * `undefined` means "no layer set a limit", which — since M2.2's
 * `BUILTIN_DEFAULTS` doesn't set it either — is a real, reachable state
 * meaning "unlimited", not "zero". Given that, setting the field to *any*
 * finite number newly imposes a restriction that did not exist before: it
 * can only ever make what's allowed a subset of what was allowed
 * previously (unlimited). That makes unset -> set a **narrowing**, exactly
 * like removing an egress host would be, even though syntactically it looks
 * like "a value appeared where there wasn't one" (which for the additive-
 * list rules above is widening). The direction is opposite because the
 * *meaning* of "absent" is opposite: for `egress.allow` absent/empty means
 * "nothing extra is allowed" (most restrictive), but for
 * `max-changed-files` absent means "no cap" (least restrictive).
 * Symmetrically: set -> unset removes a cap entirely, which is a
 * **widening**. Between two set values, a numeric increase raises the
 * ceiling (**widening**) and a decrease lowers it (**narrowing**), which
 * does match ordinary intuition once "unset = infinity" is taken seriously.
 */
const policyMaxChangedFilesRule: Rule = {
  field: "policy.max-changed-files",
  evaluate(previous, current): RuleResult {
    const prev = previous.policy["max-changed-files"];
    const curr = current.policy["max-changed-files"];
    if (prev === curr) {
      return { widened: [], narrowed: [] };
    }
    const field = "policy.max-changed-files";
    if (prev === undefined && curr !== undefined) {
      return {
        widened: [],
        narrowed: [{ field, description: `${field} set to ${curr} (was unlimited)` }],
      };
    }
    if (prev !== undefined && curr === undefined) {
      return {
        widened: [{ field, description: `${field} removed (was ${prev}, now unlimited)` }],
        narrowed: [],
      };
    }
    if (prev !== undefined && curr !== undefined) {
      return curr > prev
        ? { widened: [{ field, description: `${field} increased from ${prev} to ${curr}` }], narrowed: [] }
        : { widened: [], narrowed: [{ field, description: `${field} decreased from ${prev} to ${curr}` }] };
    }
    return { widened: [], narrowed: [] };
  },
};

const RULES: Rule[] = [
  additiveArrayRule("egress.allow", (c) => c.egress.allow),
  additiveArrayRule("egress.allow-internal", (c) => c.egress["allow-internal"]),
  booleanRule("egress.block-internal-ranges", (c) => c.egress["block-internal-ranges"], true),
  booleanRule("egress.websockets", (c) => c.egress.websockets, false),
  additiveArrayRule("git.allow-hosts", (c) => c.git["allow-hosts"]),
  additiveArrayRule("git.allow-repos", (c) => c.git["allow-repos"]),
  booleanRule("git.allow-push", (c) => c.git["allow-push"], false),
  booleanRule("git.ssh-agent", (c) => c.git["ssh-agent"], false),
  dirRule,
  booleanRule("policy.enabled", (c) => c.policy.enabled, true),
  booleanRule("policy.secret-scan", (c) => c.policy["secret-scan"], true),
  booleanRule("policy.fail-open", (c) => c.policy["fail-open"], false),
  policyMaxChangedFilesRule,
  secretsRule,
];

// ---------------------------------------------------------------------------
// Fallback: "unclassified field changed" -> widening
// ---------------------------------------------------------------------------

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Walks two already-masked (see buildFallbackPair) plain objects and reports
// one ConfigChange per differing leaf path. Recurses into plain objects so a
// change nested inside e.g. `vm` is reported as `vm.memory`, not just `vm`;
// arrays and scalars are compared as opaque leaves.
function findUnclassifiedChanges(previous: unknown, current: unknown, path: string): ConfigChange[] {
  if (deepEqual(previous, current)) {
    return [];
  }
  if (isPlainObject(previous) && isPlainObject(current)) {
    const keys = new Set([...Object.keys(previous), ...Object.keys(current)]);
    const changes: ConfigChange[] = [];
    for (const key of keys) {
      const childPath = path === "" ? key : `${path}.${key}`;
      changes.push(...findUnclassifiedChanges(previous[key], current[key], childPath));
    }
    return changes;
  }
  return [
    {
      field: path,
      description: `unclassified field '${path}' changed (no widening/narrowing rule covers it; treated as widening)`,
    },
  ];
}

function maskDirEntries(previousDirs: DirConfig[], currentDirs: DirConfig[]): { previous: Record<string, unknown>; current: Record<string, unknown> } {
  const prevNames = new Set(previousDirs.map((d) => d.name));
  const currNames = new Set(currentDirs.map((d) => d.name));
  const previous: Record<string, unknown> = {};
  const current: Record<string, unknown> = {};
  // Entries added/removed entirely are already classified by `dirRule`
  // above (regardless of their other field values), so only entries present
  // on both sides are compared here. `mode` and `rules` are deleted from a
  // full clone of the entry (rather than rebuilding a `{host, create}`
  // allow-list, as an earlier version did) since `dirRule` already
  // classifies them — everything else on the entry, including any field
  // `DirConfig` gains in the future, is left in place, so it still reaches
  // `findUnclassifiedChanges` as an unclassified (fail-closed) widening
  // instead of being silently dropped by an allow-list that forgot it.
  for (const d of previousDirs) {
    if (currNames.has(d.name)) {
      const masked = structuredClone(d) as unknown as Record<string, unknown>;
      delete masked.mode;
      delete masked.rules;
      previous[d.name] = masked;
    }
  }
  for (const d of currentDirs) {
    if (prevNames.has(d.name)) {
      const masked = structuredClone(d) as unknown as Record<string, unknown>;
      delete masked.mode;
      delete masked.rules;
      current[d.name] = masked;
    }
  }
  return { previous, current };
}

function maskSecretEntries(
  previousSecrets: Record<string, PartialSecretConfig> | undefined,
  currentSecrets: Record<string, PartialSecretConfig> | undefined,
): { previous: Record<string, unknown>; current: Record<string, unknown> } {
  const prev = previousSecrets ?? {};
  const curr = currentSecrets ?? {};
  const previous: Record<string, unknown> = {};
  const current: Record<string, unknown> = {};
  // Same principle as maskDirEntries: entries added/removed entirely, and
  // `hosts` changes on entries present in both, are already classified by
  // `secretsRule`. `hosts` is deleted from a full clone of the entry;
  // everything else — currently just `optional`, but also any future field
  // — is left in place so it fails closed rather than being dropped.
  for (const [name, entry] of Object.entries(prev)) {
    if (curr[name] !== undefined) {
      const masked = structuredClone(entry) as unknown as Record<string, unknown>;
      delete masked.hosts;
      previous[name] = masked;
    }
  }
  for (const [name, entry] of Object.entries(curr)) {
    if (prev[name] !== undefined) {
      const masked = structuredClone(entry) as unknown as Record<string, unknown>;
      delete masked.hosts;
      current[name] = masked;
    }
  }
  return { previous, current };
}

// Every leaf field a RULES entry above positively classifies, grouped by its
// parent object. This is the single source of truth `buildFallbackPair`
// deletes from a full clone of both configs — kept next to RULES (rather
// than, say, re-deriving it from RULES's `field` strings) because RULES
// mixes single-key rules (`booleanRule`/`additiveArrayRule`, one leaf each)
// with structural ones (`dirRule`/`secretsRule`/`policyMaxChangedFilesRule`,
// which classify a shape, not a single JSON path) — a flat leaf list is
// simpler to keep honest than trying to derive it mechanically from that
// mix. `dir`/`policy["max-changed-files"]` intentionally do NOT appear
// here: `dir` is handled separately below via `maskDirEntries` (add/remove
// is per-entry, not per-leaf), and `max-changed-files` is listed under
// `policy` since it IS a single leaf there.
const CLASSIFIED_LEAVES: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["egress", ["allow", "allow-internal", "block-internal-ranges", "websockets"]],
  ["git", ["allow-hosts", "allow-repos", "allow-push", "ssh-agent"]],
  ["policy", ["enabled", "secret-scan", "fail-open", "max-changed-files"]],
];

function deleteClassifiedLeaves(clone: Record<string, unknown>, group: string, keys: readonly string[]): void {
  const target = clone[group];
  if (!isPlainObject(target)) {
    return;
  }
  for (const key of keys) {
    delete target[key];
  }
}

// Builds a reduced view of both configs for `findUnclassifiedChanges` to
// compare: start from a FULL clone of each `EffectiveConfig` and delete only
// the leaves `CLASSIFIED_LEAVES` names, so whatever survives is exactly what
// RULES does not cover. This is deliberately a deny-list, not an allow-list:
// a field added to `EffectiveConfig` (top-level, or nested under `egress`/
// `git`/`policy`) with no matching entry in `CLASSIFIED_LEAVES`/RULES is
// widening by construction, because it is never deleted and so always
// reaches the recursive comparison below. An earlier version of this
// function was an allow-list — it enumerated `vm`/`agent`/`audit` explicitly
// and silently omitted `git`/`policy` and most of `egress` entirely, so a
// new field on any of those (e.g. a hypothetical `git["allow-force-push"]`)
// was invisible to the ratchet no matter what it did. Any field that is
// genuinely benign to compare-and-forget needs its own RULES entry (or a
// deliberate addition to `CLASSIFIED_LEAVES` for a boolean/array leaf) —
// there is no way to opt a new field out of this comparison by omission.
//
// `dir`/`secrets` are replaced wholesale with `maskDirEntries`/
// `maskSecretEntries`'s output rather than having leaves deleted in place:
// their add/remove classification (`dirRule`/`secretsRule`) is per-entry,
// not per-leaf, so an entry missing from one side must be excluded entirely
// here — partially masking it in place would leave a same-shaped-but-absent
// entry that double-reports the add/remove as an "unclassified" change too.
function buildFallbackPair(previous: EffectiveConfig, current: EffectiveConfig): { previous: Record<string, unknown>; current: Record<string, unknown> } {
  const dirMasked = maskDirEntries(previous.dir, current.dir);
  const secretsMasked = maskSecretEntries(previous.secrets, current.secrets);

  const prevClone = structuredClone(previous) as unknown as Record<string, unknown>;
  const currClone = structuredClone(current) as unknown as Record<string, unknown>;

  for (const [group, keys] of CLASSIFIED_LEAVES) {
    deleteClassifiedLeaves(prevClone, group, keys);
    deleteClassifiedLeaves(currClone, group, keys);
  }

  prevClone.dir = dirMasked.previous;
  currClone.dir = dirMasked.current;
  prevClone.secrets = secretsMasked.previous;
  currClone.secrets = secretsMasked.current;

  return { previous: prevClone, current: currClone };
}

// ---------------------------------------------------------------------------
// Public evaluation entry point
// ---------------------------------------------------------------------------

/**
 * Compares `previous` (the last `EffectiveConfig` this workspace was
 * accepted with) to `current` (its `EffectiveConfig` now) and returns the
 * itemized diff plus an overall verdict.
 *
 * `previous === undefined` means no trust record exists yet for this
 * workspace at all — first time `corb run` has ever seen it. That is
 * treated as requiring confirmation, the same as "everything in the config
 * is new" would be: there is nothing to compare against, so there is no
 * basis to call anything in it already-trusted, and the fallback principle
 * below (an unclassified change fails toward confirmation, never past it)
 * argues for the same conservative default here — first contact with a
 * workspace is exactly the moment a human should be looking at what it
 * grants.
 *
 * A config that widens in some fields and narrows in others is an overall
 * "requires-confirmation": any widening anywhere outweighs narrowing
 * elsewhere in the same change.
 *
 * Any field this module cannot positively classify as widening or
 * narrowing (see RULES above) defaults to widening too, via
 * `findUnclassifiedChanges` — an unclassified change must fail toward
 * requiring confirmation, never toward silently passing.
 */
export function evaluateTrust(previous: EffectiveConfig | undefined, current: EffectiveConfig): TrustEvaluation {
  if (previous === undefined) {
    return {
      verdict: "requires-confirmation",
      widened: [
        {
          field: "workspace",
          description: "no prior trust record exists for this workspace; treated as first-time widening",
        },
      ],
      narrowed: [],
    };
  }

  const widened: ConfigChange[] = [];
  const narrowed: ConfigChange[] = [];
  for (const rule of RULES) {
    const result = rule.evaluate(previous, current);
    widened.push(...result.widened);
    narrowed.push(...result.narrowed);
  }

  const fallbackPair = buildFallbackPair(previous, current);
  widened.push(...findUnclassifiedChanges(fallbackPair.previous, fallbackPair.current, ""));

  return {
    verdict: widened.length > 0 ? "requires-confirmation" : "trusted",
    widened,
    narrowed,
  };
}

// ---------------------------------------------------------------------------
// Store update
// ---------------------------------------------------------------------------

/**
 * Produces a new `TrustStore` with `workspaceKey`'s record set to `config`
 * (hashed and snapshotted), accepted at `acceptedAt`. Pure: does not mutate
 * `store`, and deliberately does not call `Date.now()` itself — the caller
 * (a later, disk-I/O-owning milestone) supplies the timestamp, which is what
 * keeps this function testable without faking the clock.
 */
export function recordAcceptance(store: TrustStore, workspaceKey: string, config: EffectiveConfig, acceptedAt: number): TrustStore {
  const record: TrustedWorkspaceRecord = {
    configHash: hashEffectiveConfig(config),
    acceptedConfig: structuredClone(config),
    acceptedAt,
  };
  return { ...store, [workspaceKey]: record };
}
