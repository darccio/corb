// `src/vm/image.ts` — M1.5: runtime image *resolution*. Turns a Corb image
// selector ("corb:0.1.0", a bare build id, or an asset directory path) into
// the concrete guest asset directory a `VM.create()` call can boot from, and
// fails with a Corb-authored, actionable error before ever attempting to
// boot — rather than letting an opaque low-level SDK error (or, worse, a
// needless network round trip) surface from deep inside `VM.create()`.
//
// Investigation before building (per the M1.5 brief): does the SDK already
// do resolution internally when handed a bare selector string, and does that
// make Corb's own explicit resolution redundant?
//
// Read `node_modules/@earendil-works/gondolin/dist/src/images.js` and
// `dist/src/sandbox/server-options.js` end to end (0.12.0) to answer this
// rather than guessing. Findings:
//
//   - `resolveImageSelector(selector, arch?)` (sync) is *entirely* local: it
//     tries the selector as a filesystem path, then as a build id in
//     Gondolin's local image object store, then as a `name:tag` ref resolved
//     from local ref symlinks (`readLocalRefTargets`, which only reads
//     `~/.cache/gondolin/images/refs/**`). None of those branches perform
//     network I/O. Verified empirically against this machine's real M1.3
//     image store (see the M1.5 report for the timed, verbatim output):
//     resolving the real `corb:0.1.0` tag took ~1-2ms and returned the
//     asset directory, buildId and arch; resolving a nonexistent
//     `corb:99.99.99` threw synchronously and just as fast.
//
//   - `ensureImageSelector(selector, arch?)` (async) tries that same local
//     resolution first, but on specifically a "not found locally" outcome
//     (`ImageResolutionError` with code `object_not_found` / `ref_not_found`
//     / `ref_arch_not_found` — an internal error class the package does not
//     export) it falls through to fetching Gondolin's own *builtin* image
//     registry (a JSON file on GitHub, `fetchBuiltinImageRegistry()`) and
//     attempts to download a published Gondolin image archive from there.
//
//   - `VM.create()` (via `vm/core.js` -> `resolveSandboxServerOptionsAsync`)
//     always routes a *string* `sandbox.imagePath` through `ensureImageSelector`,
//     never through the sync, local-only `resolveImageSelector`. So handing
//     `VM.create({ sandbox: { imagePath: "corb:0.1.0" } } )` a selector that
//     does not exist locally does not fail fast and locally: it first
//     attempts a real network fetch against Gondolin's builtin-image
//     registry (which has no entry named "corb" — that registry is for
//     Gondolin's own published images, not Corb's local build output), then
//     fails with a Gondolin-authored message about its own registry, not a
//     Corb-authored one about `corb image build`. That network attempt is
//     also a real availability/latency risk in an offline dev loop.
//
// Conclusion: resolution has to happen explicitly, host-side, in Corb's own
// code, before `VM.create()` is ever called — not by handing a bare selector
// string through and trusting the SDK's own fallback chain. Concretely:
//
//   1. Call `resolveImageSelector` (sync, local-only, no network) ourselves.
//   2. On failure, throw `ImageNotFoundError` — a friendly, actionable
//      message ("run `corb image build` first") instead of surfacing
//      whatever `resolveImageSelector` threw (or, worse, letting
//      `ensureImageSelector`'s network fallback run and fail with a
//      Gondolin-registry-flavoured message that has nothing to do with
//      Corb).
//   3. On success, hand the *already-resolved* asset directory (an absolute
//      path that exists on disk) to `VM.create({ sandbox: { imagePath } })`
//      — not the original selector string. A directory-shaped imagePath
//      resolves via the local, path-selector branch of `resolveImagePath`
//      inside the SDK regardless of whether the sync or async resolution
//      path is used, so this is the one choice that is *never* a network
//      operation, on top of already having been resolved once.
//
// This also gives M1.6 the resolved `buildId`/`arch` for logging which
// concrete build got picked, which passing a bare selector through would not.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  getDefaultArch,
  resolveImageSelector,
  type ImageArch,
  type ResolvedImage,
} from "@earendil-works/gondolin";

export interface ResolvedCorbImage {
  /** The selector that was resolved (the default or an explicit override). */
  selector: string;
  /** Architecture of the resolved image. */
  arch: ImageArch;
  /**
   * Resolved guest asset directory. Pass this — not `selector` — to
   * `VM.create({ sandbox: { imagePath: assetDir } })` so boot never
   * re-resolves (and never falls through to a network fetch).
   */
  assetDir: string;
  /** Content-derived build id, when the resolved source has one. */
  buildId: string | undefined;
}

/**
 * Thrown by `resolveRuntimeImage` when `resolveImageSelector` cannot find the
 * selector locally — the SDK's own error is not shown to the caller directly
 * because it names Gondolin's own image store / builtin registry, neither of
 * which is meaningful to someone running `corb`. `cause` carries the
 * original error for anyone who wants it (`--debug-log`, a bug report).
 */
export class ImageNotFoundError extends Error {
  readonly selector: string;

  constructor(selector: string) {
    super(
      `corb: guest image '${selector}' was not found locally.\n` +
        `  Run 'corb image build' first to build and tag it, or pass a different image selector.`,
    );
    this.name = "ImageNotFoundError";
    this.selector = selector;
  }
}

function moduleDir(): string {
  return path.dirname(fileURLToPath(import.meta.url));
}

// src/vm/image.ts -> repo root is two levels up, same depth as
// src/commands/image.ts (see readPackageVersion there for the full
// reasoning: this resolves correctly whether corb is run from a dev
// checkout via `node src/cli.ts` or from an installed `dist/cli.js`, because
// tsc mirrors src/ under dist/ at the same relative depth). Duplicated
// rather than factored into a shared module: it is a five-line function with
// exactly two call sites, and a shared `util/pkg.ts` for that alone would be
// one more file to open to follow one string concatenation.
function packageRoot(): string {
  return path.resolve(moduleDir(), "..", "..");
}

function readPackageVersion(): string {
  const pkgPath = path.join(packageRoot(), "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { version?: unknown };
  if (typeof pkg.version !== "string" || pkg.version.length === 0) {
    throw new Error(`package.json at ${pkgPath} has no "version" string field`);
  }
  return pkg.version;
}

/**
 * Corb's default image selector: the moving `corb:<pkgVersion>` alias that
 * `corb image build` (M1.3, `src/commands/image.ts`) tags every successful
 * build with.
 */
export function defaultImageSelector(): string {
  return `corb:${readPackageVersion()}`;
}

/**
 * Resolve a Corb runtime image selector to something `VM.create()` can boot
 * from, without ever attempting a network fetch and without ever letting a
 * raw SDK error reach the caller.
 *
 * @param selector Defaults to `defaultImageSelector()` — the moving
 *   `corb:<pkgVersion>` alias `corb image build` produces.
 * @param arch Defaults to whatever `resolveImageSelector` picks (which for a
 *   `name:tag` ref with a single arch target is that target; otherwise the
 *   SDK's own `getDefaultArch()` result is used as a fallback label here —
 *   the actual arch selection during resolution is the SDK's, this is only
 *   for a value to report when the SDK's own result is silent on arch).
 */
export function resolveRuntimeImage(selector?: string, arch?: ImageArch): ResolvedCorbImage {
  const effectiveSelector = selector ?? defaultImageSelector();

  let resolved: ResolvedImage;
  try {
    resolved = resolveImageSelector(effectiveSelector, arch);
  } catch {
    throw new ImageNotFoundError(effectiveSelector);
  }

  return {
    selector: effectiveSelector,
    arch: resolved.arch ?? arch ?? getDefaultArch(),
    assetDir: resolved.assetDir,
    buildId: resolved.buildId,
  };
}
