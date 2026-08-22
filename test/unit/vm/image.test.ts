// Unit tests for `src/vm/image.ts`. These are hermetic — each test points
// `GONDOLIN_IMAGE_STORE` at a fresh temp directory and plants a synthetic
// image object in it via the real `@earendil-works/gondolin` SDK functions
// (`setImageRef`), so the suite exercises real SDK resolution logic without
// depending on any image actually being built on the host machine running
// `npm test`.
//
// That is deliberately *separate* from the M1.5 verification requirement to
// demonstrate resolution against the real, locally-built `corb:0.1.0` image
// from M1.3/M1.4 — that check was run by hand against this machine's actual
// `~/.cache/gondolin` image store and its verbatim output is in the M1.5
// report, rather than being wired into the committed suite: a test that
// only passes on a machine that happens to have already run
// `corb image build` would make `npm test` non-portable and CI-unfriendly.
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setImageRef, type ImageArch } from "@earendil-works/gondolin";
import { ImageNotFoundError, defaultImageSelector, resolveRuntimeImage } from "../../../src/vm/image.ts";

function readPkgVersion(): string {
  const pkgPath = fileURLToPath(new URL("../../../package.json", import.meta.url));
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { version: string };
  return pkg.version;
}

describe("vm/image", () => {
  let storeDir: string;
  let previousStore: string | undefined;

  beforeEach(() => {
    storeDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-image-store-"));
    previousStore = process.env.GONDOLIN_IMAGE_STORE;
    process.env.GONDOLIN_IMAGE_STORE = storeDir;
  });

  afterEach(() => {
    if (previousStore === undefined) {
      delete process.env.GONDOLIN_IMAGE_STORE;
    } else {
      process.env.GONDOLIN_IMAGE_STORE = previousStore;
    }
    fs.rmSync(storeDir, { recursive: true, force: true });
  });

  /**
   * Plants a real, minimal local image object + ref in the (isolated,
   * per-test) Gondolin image store — enough for `resolveImageSelector` to
   * resolve it for real, without needing an actual bootable kernel/rootfs.
   */
  function plantFakeImage(buildId: string, arch: ImageArch, reference: string): string {
    const objectDir = path.join(storeDir, "objects", buildId);
    fs.mkdirSync(objectDir, { recursive: true });
    fs.writeFileSync(
      path.join(objectDir, "manifest.json"),
      JSON.stringify({
        buildId,
        config: { arch },
        assets: { kernel: "vmlinuz-virt", initramfs: "initramfs.cpio.lz4", rootfs: "rootfs.ext4" },
      }),
    );
    for (const name of ["vmlinuz-virt", "initramfs.cpio.lz4", "rootfs.ext4"]) {
      fs.writeFileSync(path.join(objectDir, name), "");
    }
    setImageRef(reference, buildId, arch);
    return objectDir;
  }

  it("resolves a locally tagged selector to its asset directory, arch and build id", () => {
    const buildId = randomUUID();
    const objectDir = plantFakeImage(buildId, "x86_64", "corb-test:1.0.0");

    const resolved = resolveRuntimeImage("corb-test:1.0.0");

    expect(resolved).toEqual({
      selector: "corb-test:1.0.0",
      arch: "x86_64",
      assetDir: objectDir,
      buildId,
    });
  });

  it("throws a friendly, actionable ImageNotFoundError for a selector that was never built", () => {
    let thrown: unknown;
    try {
      resolveRuntimeImage("corb-test:99.99.99");
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBeInstanceOf(ImageNotFoundError);
    const err = thrown as ImageNotFoundError;
    expect(err.selector).toBe("corb-test:99.99.99");
    expect(err.message).toContain("corb-test:99.99.99");
    expect(err.message).toContain("corb image build");
  });

  it("does not leak the raw SDK error message (which names Gondolin's own registry, not corb's)", () => {
    let thrown: unknown;
    try {
      resolveRuntimeImage("corb-test:99.99.99");
    } catch (err) {
      thrown = err;
    }
    const message = (thrown as Error).message;
    expect(message).not.toContain("builtin registry");
    expect(message).not.toContain("ImageResolutionError");
  });

  it("defaultImageSelector() reads the pinned pkgVersion, matching corb image build's own moving alias", () => {
    expect(defaultImageSelector()).toBe(`corb:${readPkgVersion()}`);
  });

  it("resolveRuntimeImage() with no selector resolves the default corb:<pkgVersion> alias", () => {
    const buildId = randomUUID();
    const pkgVersion = readPkgVersion();
    plantFakeImage(buildId, "x86_64", `corb:${pkgVersion}`);

    const resolved = resolveRuntimeImage();

    expect(resolved.selector).toBe(`corb:${pkgVersion}`);
    expect(resolved.buildId).toBe(buildId);
  });

  it("an explicit arch selects that arch's target when a ref has more than one", () => {
    const x64BuildId = randomUUID();
    const armBuildId = randomUUID();
    plantFakeImage(x64BuildId, "x86_64", "corb-test:multi");
    plantFakeImage(armBuildId, "aarch64", "corb-test:multi");

    expect(resolveRuntimeImage("corb-test:multi", "x86_64").buildId).toBe(x64BuildId);
    expect(resolveRuntimeImage("corb-test:multi", "aarch64").buildId).toBe(armBuildId);
  });
});
