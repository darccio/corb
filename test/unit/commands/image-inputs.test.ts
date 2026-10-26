import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { BuildConfig } from "@earendil-works/gondolin";
import { afterEach, describe, expect, it } from "vitest";
import { computeContentHash } from "../../../src/commands/image.ts";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-image-inputs-"));
  dirs.push(dir);
  const config: BuildConfig = { arch: "x86_64", distro: "alpine" };
  return { dir, config };
}

describe("image build input hash", () => {
  for (const field of ["rootfsInit", "initramfsInit", "rootfsInitExtra"] as const) {
    it(`hashes config-relative init.${field} bytes`, () => {
      const { dir, config } = fixture();
      config.init = { [field]: "init.sh" };
      fs.writeFileSync(path.join(dir, "init.sh"), "before");
      const before = computeContentHash(config, dir);
      fs.writeFileSync(path.join(dir, "init.sh"), "after");
      expect(computeContentHash(config, dir)).not.toBe(before);
    });
    it(`rejects missing init.${field}`, () => {
      const { dir, config } = fixture();
      config.init = { [field]: "absent.sh" };
      expect(() => computeContentHash(config, dir)).toThrow(/ENOENT/);
    });
    it(`rejects unreadable init.${field}`, () => {
      const { dir, config } = fixture();
      config.init = { [field]: "." };
      expect(() => computeContentHash(config, dir)).toThrow();
    });
  }

  it("separates adjacent file bytes and field names", () => {
    const { dir, config } = fixture();
    config.init = { rootfsInit: "a", initramfsInit: "b" };
    fs.writeFileSync(path.join(dir, "a"), "a");
    fs.writeFileSync(path.join(dir, "b"), "bc");
    const first = computeContentHash(config, dir);
    fs.writeFileSync(path.join(dir, "a"), "ab");
    fs.writeFileSync(path.join(dir, "b"), "c");
    expect(computeContentHash(config, dir)).not.toBe(first);
    config.init = { rootfsInit: "b", initramfsInit: "a" };
    expect(computeContentHash(config, dir)).not.toBe(first);
  });

  it("hashes copy bytes, destinations, effective config and deterministic order", () => {
    const { dir, config } = fixture();
    fs.writeFileSync(path.join(dir, "a"), "payload");
    fs.writeFileSync(path.join(dir, "b"), "second");
    config.postBuild = { copy: [{ src: "a", dest: "/a" }, { src: "b", dest: "/b" }] };
    const first = computeContentHash(config, dir);
    expect(computeContentHash(structuredClone(config), dir)).toBe(first);
    config.postBuild.copy!.reverse();
    expect(computeContentHash(config, dir)).not.toBe(first);
    config.postBuild.copy!.reverse();
    config.postBuild.copy![0]!.dest = "/changed";
    expect(computeContentHash(config, dir)).not.toBe(first);
    config.postBuild.copy![0]!.dest = "/a";
    fs.writeFileSync(path.join(dir, "a"), "changed");
    expect(computeContentHash(config, dir)).not.toBe(first);
    fs.writeFileSync(path.join(dir, "a"), "payload");
    config.arch = "aarch64";
    expect(computeContentHash(config, dir)).not.toBe(first);
  });

  it("rejects missing copy inputs", () => {
    const { dir, config } = fixture();
    config.postBuild = { copy: [{ src: "absent", dest: "/a" }] };
    expect(() => computeContentHash(config, dir)).toThrow(/ENOENT/);
  });
});
