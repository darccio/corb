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
