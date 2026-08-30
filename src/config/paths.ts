// `src/config/paths.ts` — M2.5: pure path-resolution helpers for Corb's own
// on-disk config directory (XDG-flavored, per `docs/design.md`'s workspace
// config discussion: `~/.config/corb` holds `config.toml` and
// `trusted.json`). Mirrors `src/commands/image.ts`'s `corbCacheDir()` /
// `CORB_CACHE_DIR` pattern exactly — same shape, same reasoning: tests need
// to point this somewhere other than the real user config dir, without
// threading an override through every call site by hand.
//
// `~/.config/corb/workspaces/<name>.toml` (named-workspace-file resolution)
// is reserved for a later milestone. There is deliberately no
// `workspacesDir()`-style helper here yet — this item's `corb explain`/
// `corb run --dry-run` only ever resolve a directory path, never a name — so
// a future item extending this file should not be surprised by its absence.
import os from "node:os";
import path from "node:path";

/** Corb's own config directory. Overridable via `CORB_CONFIG_DIR`, e.g. so tests never touch the real `~/.config/corb`. */
export function corbConfigDir(): string {
  return process.env.CORB_CONFIG_DIR ?? path.join(os.homedir(), ".config", "corb");
}

/** Path to `config.toml` inside `configDir` (defaults to `corbConfigDir()`). Optional on disk — its absence is not an error. */
export function configTomlPath(configDir: string = corbConfigDir()): string {
  return path.join(configDir, "config.toml");
}

/** Path to `trusted.json` inside `configDir` (defaults to `corbConfigDir()`). Optional on disk — its absence means "never run before". */
export function trustStorePath(configDir: string = corbConfigDir()): string {
  return path.join(configDir, "trusted.json");
}

/**
 * Corb's own state directory — distinct from `corbConfigDir()` because
 * `~/.config` and `~/.local/state` are conventionally different XDG
 * categories (config is user-edited intent, state is Corb-generated
 * output, e.g. the audit log). Overridable via `CORB_STATE_DIR`, same
 * pattern as `CORB_CONFIG_DIR`.
 */
export function corbStateDir(): string {
  return process.env.CORB_STATE_DIR ?? path.join(os.homedir(), ".local", "state", "corb");
}

/** Default path to the unified audit log (`docs/design.md` §3/§6) inside `stateDir` (defaults to `corbStateDir()`). This is only ever a default a caller may pass on to `src/policy/audit.ts` — that module takes a plain path and does not import this file. */
export function defaultAuditPath(stateDir: string = corbStateDir()): string {
  return path.join(stateDir, "audit.jsonl");
}

/**
 * Directory holding Corb's own session sidecars (`docs/design.md` §7, §3)
 * inside `stateDir` (defaults to `corbStateDir()`) — one `<id>.json` file per
 * session, `id` matching Gondolin's own `vm.id`. This is only ever a default
 * a caller may pass on to `src/vm/registry.ts` — that module takes a plain
 * directory path and does not import this file, mirroring `defaultAuditPath`'s
 * own relationship to `src/policy/audit.ts`.
 */
export function sessionsStateDir(stateDir: string = corbStateDir()): string {
  return path.join(stateDir, "sessions");
}
