// `corb image build` — wraps the Gondolin SDK's build/tag plumbing to
// produce Corb's guest image.
//
// Call sequence (verified against
// node_modules/@earendil-works/gondolin/dist/src/images.js for 0.12.0):
//
//   1. buildAssets(config, options) writes kernel/initramfs/rootfs plus a
//      manifest.json (with a content-derived `buildId`) into `outputDir`.
//   2. importImageFromDirectory(outputDir) copies those assets into
//      Gondolin's own image object store (getImageStoreDirectory()/objects/
//      <buildId>) — a required step: tagImage()/setImageRef() resolve a
//      `source` through resolveImageSelector() and then call
//      ensureImageObjectExists(buildId), which only looks in the image
//      store, never at an arbitrary path. Passing the raw buildAssets output
//      directory straight to tagImage() (skipping the import) resolves the
//      buildId fine but then fails at ensureImageObjectExists because
//      nothing has been copied into the store yet.
//   3. tagImage(buildId, targetReference, arch) writes a ref symlink
//      (getImageStoreDirectory()/refs/<name>/<tag>/<arch> -> the object
//      dir) pointing at the imported object. Called twice here: once for
//      the full content-hash tag, once for the moving `corb:<pkgVersion>`
//      alias.
//
// Note the two distinct hashes in play: Gondolin's own `buildId` is a
// UUID derived from the manifest's asset checksums (see
// build/shared.js `computeAssetBuildId`) and is purely an implementation
// detail of the SDK's object store. Corb's own tag
// (`corb:<pkgVersion>-<arch>-<hash>`) is computed independently below from
// the effective BuildConfig plus the bytes of every postBuild.copy source
// file (which is where the guest binaries and overlay data enter the
// image) — this is Corb's own scheme, not something the SDK provides.
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import {
  buildAssets,
  getDefaultArch,
  getImageStoreDirectory,
  importImageFromDirectory,
  tagImage,
  validateBuildConfig,
  type BuildConfig,
  type ImageArch,
  type LocalImageRef,
} from "@earendil-works/gondolin";

// image/verify.ts (M1.4) lives outside src/ deliberately — it is not part
// of tsc's compiled program (tsconfig.json's rootDir is "src", and a static
// import of a file outside it fails to compile with TS6059). Loading it
// through a dynamic import() whose specifier is a runtime-computed string
// (never a string literal) keeps tsc from trying to resolve or include it
// in the program at all, so it never hits that rootDir check; Node's own
// native TypeScript support (the same "erasable syntax" support
// `src/cli.ts` relies on for `npm run dev`) then loads and runs it directly,
// whether corb is running from a dev checkout or from `dist/cli.js`.
interface GateResult {
  name: string;
  ok: boolean;
  detail: string;
}

interface VerifyReport {
  ok: boolean;
  gates: GateResult[];
}

type VerifyImageFn = (
  assetDir: string,
  options?: { allowedHosts?: string[]; sessionLabel?: string },
) => Promise<VerifyReport>;

async function loadVerifyImage(): Promise<VerifyImageFn> {
  const verifyPath = path.join(packageRoot(), "image", "verify.ts");
  const mod = (await import(pathToFileURL(verifyPath).href)) as { verifyImage: VerifyImageFn };
  return mod.verifyImage;
}

function moduleDir(): string {
  return path.dirname(fileURLToPath(import.meta.url));
}

// src/commands/image.ts -> repo root is two levels up. tsc mirrors src/
// under dist/ (rootDir: src, outDir: dist), so the compiled
// dist/commands/image.js sits at the same depth relative to the package
// root, and this resolves correctly either way — which is the point: a
// default config path that does not depend on process.cwd() or on whether
// we're running from a dev checkout (`node src/cli.ts`) or an installed
// package (`dist/cli.js`).
function packageRoot(): string {
  return path.resolve(moduleDir(), "..", "..");
}

function defaultConfigPath(): string {
  return path.join(packageRoot(), "image", "corb-image.json");
}

function readPackageVersion(): string {
  const pkgPath = path.join(packageRoot(), "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { version?: unknown };
  if (typeof pkg.version !== "string" || pkg.version.length === 0) {
    throw new Error(`package.json at ${pkgPath} has no "version" string field`);
  }
  return pkg.version;
}

function parseArch(value: string | undefined): ImageArch | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (value === "x86_64" || value === "aarch64") {
    return value;
  }
  throw new Error(`invalid --arch '${value}': expected 'x86_64' or 'aarch64'`);
}

interface ImageBuildOptions {
  configPath: string;
  tagOverride: string | undefined;
  arch: ImageArch;
}

function parseImageBuildArgs(argv: string[]): ImageBuildOptions {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: "string" },
      tag: { type: "string" },
      arch: { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });
  return {
    configPath: values.config !== undefined ? path.resolve(values.config) : defaultConfigPath(),
    tagOverride: values.tag,
    arch: parseArch(values.arch) ?? getDefaultArch(),
  };
}

function corbCacheDir(): string {
  return process.env.CORB_CACHE_DIR ?? path.join(os.homedir(), ".cache", "corb");
}

/**
 * Corb's own content hash for the image tag: the effective BuildConfig
 * (after the --arch override is applied) plus the bytes of every
 * postBuild.copy source file, in config order. This is what actually
 * changes when the guest binaries (dropcap) or the overlay data
 * (suid-allowlist.txt, image.json) change, which the BuildConfig JSON alone
 * would not capture.
 */
function computeContentHash(config: BuildConfig, configDir: string): string {
  const hash = createHash("sha256");
  hash.update(JSON.stringify(config));
  for (const entry of config.postBuild?.copy ?? []) {
    const src = path.resolve(configDir, entry.src);
    hash.update(entry.dest);
    hash.update(fs.readFileSync(src));
  }
  return hash.digest("hex").slice(0, 8);
}

/**
 * Go's `GOARCH` naming (what the `guest-<GOARCH>` Makefile targets actually
 * produce, in `guest/build/<GOARCH>/`) differs from Gondolin's own
 * `Architecture`/`ImageArch` naming (`x86_64`/`aarch64`) used everywhere
 * else in this file. This is the one place that gap needs bridging.
 */
export const GOARCH_BY_IMAGE_ARCH: Record<ImageArch, string> = {
  x86_64: "amd64",
  aarch64: "arm64",
};

/**
 * Substitutes the `{arch}` placeholder (see corb-image.json's
 * `postBuild.copy` guest-binary entries) with the GOARCH string for
 * `arch`, keyed off the same `config.arch` every other arch-aware path in
 * this file already uses. A no-op for any `src` that doesn't contain the
 * placeholder (e.g. the overlay config-file copy entries).
 */
export function resolveArchPlaceholders(raw: Record<string, unknown>, arch: ImageArch): void {
  const postBuild = raw.postBuild as { copy?: { src: string }[] } | undefined;
  const goArch = GOARCH_BY_IMAGE_ARCH[arch];
  for (const entry of postBuild?.copy ?? []) {
    entry.src = entry.src.replace("{arch}", goArch);
  }
}

export interface ImageBuildReport {
  configPath: string;
  arch: ImageArch;
  outputDir: string;
  buildId: string;
  buildMs: number;
  verify: VerifyReport;
  primaryTag: LocalImageRef;
  aliasTag: LocalImageRef;
  imageStoreDirectory: string;
}

/**
 * Thrown when the M1.4 in-VM gate suite (image/verify.ts) fails against
 * freshly built assets. `gates` carries the full report so a caller can
 * inspect which gate(s) failed and why, not just a flattened message.
 */
export class ImageVerificationError extends Error {
  readonly gates: GateResult[];

  constructor(gates: GateResult[]) {
    const failed = gates.filter((g) => !g.ok);
    const summary = failed.map((g) => `${g.name}: ${g.detail}`).join(" | ");
    super(
      `corb image build: image verification failed (${failed.length} of ${gates.length} gate${gates.length === 1 ? "" : "s"} failed): ${summary}`,
    );
    this.name = "ImageVerificationError";
    this.gates = gates;
  }
}

export async function imageBuild(argv: string[]): Promise<ImageBuildReport> {
  const opts = parseImageBuildArgs(argv);
  const configDir = path.dirname(opts.configPath);
  const rawText = fs.readFileSync(opts.configPath, "utf8");
  const raw = JSON.parse(rawText) as Record<string, unknown>;
  // Arch is always the SDK's own getDefaultArch() (or the explicit --arch
  // override), never whatever happens to be hardcoded in the config file.
  raw.arch = opts.arch;
  resolveArchPlaceholders(raw, opts.arch);
  if (!validateBuildConfig(raw)) {
    throw new Error(`invalid build config at ${opts.configPath}`);
  }
  const config = raw as BuildConfig;

  const pkgVersion = readPackageVersion();
  const contentHash = computeContentHash(config, configDir);
  const primaryReference = opts.tagOverride ?? `corb:${pkgVersion}-${config.arch}-${contentHash}`;
  const movingAlias = `corb:${pkgVersion}`;

  // Corb's own build-artifact directory. Deliberately separate from
  // wherever getImageStoreDirectory() resolves to — that is Gondolin's own
  // internal object store and is not ours to redirect.
  const outputDir = path.join(corbCacheDir(), "image-build", config.arch);
  fs.mkdirSync(outputDir, { recursive: true });

  process.stderr.write(`corb image build: config=${opts.configPath}\n`);
  process.stderr.write(`corb image build: arch=${config.arch}\n`);
  process.stderr.write(`corb image build: output=${outputDir}\n`);

  const buildStart = Date.now();
  const result = await buildAssets(config, {
    outputDir,
    configDir,
    verbose: true,
  });
  const buildMs = Date.now() - buildStart;

  // Precondition of tagging (M1.4): boot the assets just written to disk —
  // not yet imported into Gondolin's image store, not yet tagged — in a
  // throwaway VM and run the gate suite against them. On any failure, the
  // already-written buildAssets() output is left on disk (useful for
  // debugging) but nothing gets imported or tagged.
  process.stderr.write(`corb image build: verifying guest image at ${result.outputDir}\n`);
  const verifyImage = await loadVerifyImage();
  const verify = await verifyImage(result.outputDir, {
    sessionLabel: `corb-image-verify:${config.arch}`,
  });
  for (const gate of verify.gates) {
    process.stderr.write(`corb image build: verify [${gate.ok ? "PASS" : "FAIL"}] ${gate.name}: ${gate.detail}\n`);
  }
  if (!verify.ok) {
    throw new ImageVerificationError(verify.gates);
  }

  const imported = importImageFromDirectory(result.outputDir);
  const primaryTag = tagImage(imported.buildId, primaryReference, config.arch);
  const aliasTag = tagImage(imported.buildId, movingAlias, config.arch);

  return {
    configPath: opts.configPath,
    arch: config.arch,
    outputDir: result.outputDir,
    buildId: imported.buildId,
    buildMs,
    verify,
    primaryTag,
    aliasTag,
    imageStoreDirectory: getImageStoreDirectory(),
  };
}

export async function runImageCommand(argv: string[]): Promise<void> {
  const [sub, ...rest] = argv;
  if (sub === "build") {
    const report = await imageBuild(rest);
    console.log(`corb image build: done in ${(report.buildMs / 1000).toFixed(1)}s`);
    console.log(`corb image build: verify passed (${report.verify.gates.length}/${report.verify.gates.length} gates)`);
    console.log(`corb image build: buildId=${report.buildId}`);
    console.log(
      `corb image build: tagged ${report.primaryTag.reference} (${JSON.stringify(report.primaryTag.targets)})`,
    );
    console.log(
      `corb image build: tagged ${report.aliasTag.reference} (${JSON.stringify(report.aliasTag.targets)})`,
    );
    console.log(`corb image build: gondolin image store at ${report.imageStoreDirectory}`);
    return;
  }
  throw new Error(`corb image: unsupported subcommand '${sub ?? ""}' (only 'build' exists so far)`);
}
