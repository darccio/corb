import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { bindLayerArtifact, assertCompatiblePackagePlan, assertPinsMatchDefinition, hashRecipePins, normalizeTargetPins, parseLayerLock, readLayerLock, recipePins, refreshLayerPins, serializeLayerLock, validateApkindexChecksum } from "../../../src/layer/pins.ts";
import { validateArtifactReference } from "../../../src/layer/reference.ts";
import { checksum, definition, hash, pins } from "./fixtures.ts";

const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
function temporary() { const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-pins-")); dirs.push(dir); return dir; }

describe("shareable pins", () => {
  it("preserves both targets and orders repositories and packages", () => {
    const arm = pins();
    arm.index = arm.index.map((row) => ({ ...row, url: row.url.replace("x86_64", "aarch64") }));
    const lock = { version: 1 as const, target: { x86_64: { ...pins(), index: [...pins().index].reverse(), package: [...pins().package].reverse() }, aarch64: arm } };
    expect(parseLayerLock(serializeLayerLock(lock)).target).toEqual({ x86_64: pins(), aarch64: arm });
    assertPinsMatchDefinition(pins(), definition(), "x86_64");
  });
  it.each([
    { os: "darwin" }, { abi: "glibc" }, { "alpine-branch": "edge" }, { "definition-sha256": "bad" }, { buildId: "local" },
    { index: [pins().index[0]] }, { index: [pins().index[0], pins().index[0]] },
    { index: [{ ...pins().index[0], url: "https://mirror.example/main/APKINDEX.tar.gz" }, pins().index[1]] },
    { installer: undefined }, { installer: { ...pins().installer, repository: "community" } },
    { package: [...pins().package, pins().package[0]] },
    { package: [{ ...pins().package[0], version: "1.0 @edge" }] },
    { package: [{ ...pins().package[0], version: "1/0" }] },
    { package: [{ ...pins().package[0], requested: "true" }] },
    { package: [{ ...pins().package[0], "archive-sha256": hash("A") }] },
    { package: [{ ...pins().package[0], path: "/tmp/x" }] },
  ])("rejects malformed target %j", (change) => {
    expect(() => normalizeTargetPins({ ...pins(), ...change }, "x86_64")).toThrow();
  });
  it.each(["Q1AAAA", `Q1${Buffer.alloc(19).toString("base64")}`, `${checksum.slice(0, -2)}B=`, "Q2" + checksum.slice(2)])("rejects malformed index checksum %s", (value) => {
    expect(() => validateApkindexChecksum(value)).toThrow();
  });
  it.each(["version=2\n[target]", "version=1\nunknown=1\n[target]", "version=1\n[target.ppc64]", "version=1\nversion=1\n[target]", "[target]"])("rejects malformed document %s", (text) => {
    expect(() => parseLayerLock(text)).toThrow();
  });
  it("rejects stale definitions and requested rows with missing or extra names", () => {
    expect(() => assertPinsMatchDefinition({ ...pins(), "definition-sha256": hash() }, definition(), "x86_64")).toThrow("do not match");
    expect(() => assertPinsMatchDefinition({ ...pins(), package: pins().package.map((row) => ({ ...row, requested: true })) }, definition(), "x86_64")).toThrow("exactly");
  });
  it("omits index, installer and package TOML rows for command-only pins", () => {
    const target = { ...pins(), index: [], installer: undefined, package: [] };
    const text = serializeLayerLock({ version: 1, target: { x86_64: target } });
    expect(text).not.toMatch(/\.index|\.installer|\.package/);
    expect(parseLayerLock(text).target.x86_64?.package).toEqual([]);
  });
  it("keeps candidate closure independent of actual additions", () => {
    const recipe = recipePins(pins(), "x86_64");
    expect(recipe.package.map((row) => row.name)).toEqual(["go", "musl"]);
    const { requested: _requested, ...go } = recipe.package[0]!;
    expect(() => assertCompatiblePackagePlan(recipe, [{ action: "add", ...go }])).not.toThrow();
    expect(() => assertCompatiblePackagePlan(recipe, [])).not.toThrow();
    for (const action of ["upgrade", "downgrade", "replace", "reinstall", "remove"] as const) expect(() => assertCompatiblePackagePlan(recipe, [{ action, ...go }])).toThrow("incompatible base");
    expect(() => assertCompatiblePackagePlan(recipe, [{ action: "add", ...go, version: "999" }])).toThrow("unbundled");
    expect(() => assertCompatiblePackagePlan(recipe, [{ action: "add", ...go, name: "other" }])).toThrow("unbundled");
  });
  it("excludes artifact binding from the recipe identity", () => {
    expect(hashRecipePins(pins(), "x86_64")).toBe(hashRecipePins({ ...pins(), artifact: `ghcr.io/org/layer@sha256:${hash()}` }, "x86_64"));
  });
  it("distinguishes missing files, dangling links, unreadable files and malformed content", () => {
    const dir = temporary();
    expect(readLayerLock(dir)).toBeUndefined();
    const file = path.join(dir, "corb.sum");
    fs.symlinkSync("missing", file);
    expect(() => readLayerLock(dir)).toThrow("dangling");
    fs.unlinkSync(file);
    fs.writeFileSync(file, "malformed");
    expect(() => refreshLayerPins(dir, "x86_64", pins())).toThrow();
    expect(fs.readFileSync(file, "utf8")).toBe("malformed");
    vi.spyOn(fs, "readFileSync").mockImplementation(() => { throw Object.assign(new Error("permission denied"), { code: "EACCES" }); });
    expect(() => readLayerLock(dir)).toThrow("permission denied");
  });
  it("refreshes a symlink target atomically, retains the other target and clears artifact", () => {
    const dir = temporary();
    const target = path.join(dir, "pins.toml");
    const arm = pins();
    arm.index = arm.index.map((row) => ({ ...row, url: row.url.replace("x86_64", "aarch64") }));
    fs.writeFileSync(target, serializeLayerLock({ version: 1, target: { aarch64: arm } }));
    fs.symlinkSync("pins.toml", path.join(dir, "corb.sum"));
    refreshLayerPins(dir, "x86_64", { ...pins(), artifact: `ghcr.io/org/layer@sha256:${hash()}` });
    expect(fs.lstatSync(path.join(dir, "corb.sum")).isSymbolicLink()).toBe(true);
    expect(readLayerLock(dir)?.target).toEqual({ x86_64: pins(), aarch64: arm });
    expect(fs.statSync(target).mode & 0o777).toBe(0o600);
  });
  it.each(["read", "stage"])("refuses a lock symlink retargeted during %s without clobbering either real file", (phase) => {
    const dir = temporary();
    const file = path.join(dir, "corb.sum");
    const targetA = path.join(dir, "a.toml");
    const targetB = path.join(dir, "b.toml");
    const prior = serializeLayerLock({ version: 1, target: { x86_64: pins() } });
    fs.writeFileSync(targetA, prior);
    fs.writeFileSync(targetB, "malformed old content");
    fs.symlinkSync("a.toml", file);
    let changed = false;
    const retarget = () => {
      if (changed) return;
      changed = true;
      fs.unlinkSync(file);
      fs.symlinkSync("b.toml", file);
    };
    if (phase === "read") {
      const read = fs.readFileSync.bind(fs);
      vi.spyOn(fs, "readFileSync").mockImplementation((...args: Parameters<typeof fs.readFileSync>) => {
        const bytes = read(...args);
        if (args[0] === targetA) retarget();
        return bytes;
      });
    } else {
      const rename = fs.renameSync.bind(fs);
      vi.spyOn(fs, "renameSync").mockImplementation((from, to) => {
        rename(from, to);
        retarget();
      });
    }
    expect(() => refreshLayerPins(dir, "x86_64", pins())).toThrow("changed during pin refresh");
    expect(changed).toBe(true);
    expect(fs.readFileSync(targetA, "utf8")).toBe(prior);
    expect(fs.readFileSync(targetB, "utf8")).toBe("malformed old content");
    expect(fs.readlinkSync(file)).toBe("b.toml");
    expect(fs.readdirSync(dir).sort()).toEqual(["a.toml", "b.toml", "corb.sum"]);
  });
  it("refuses replacement of the captured target before publication", () => {
    const dir = temporary();
    const file = path.join(dir, "corb.sum");
    fs.writeFileSync(file, serializeLayerLock({ version: 1, target: { x86_64: pins() } }));
    const rename = fs.renameSync.bind(fs);
    vi.spyOn(fs, "renameSync").mockImplementation((from, to) => {
      rename(from, to);
      fs.unlinkSync(file);
      fs.writeFileSync(file, "malformed replacement");
    });
    expect(() => refreshLayerPins(dir, "x86_64", pins())).toThrow("changed during pin refresh");
    expect(fs.readFileSync(file, "utf8")).toBe("malformed replacement");
    expect(fs.readdirSync(dir)).toEqual(["corb.sum"]);
  });
  it("preserves pins and symlink on a real filesystem write failure", () => {
    const dir = temporary();
    const store = path.join(dir, "readonly");
    fs.mkdirSync(store);
    const target = path.join(store, "pins.toml");
    const prior = serializeLayerLock({ version: 1, target: { x86_64: pins() } });
    fs.writeFileSync(target, prior);
    fs.symlinkSync(target, path.join(dir, "corb.sum"));
    fs.chmodSync(store, 0o500);
    try {
      expect(() => refreshLayerPins(dir, "x86_64", pins())).toThrow(/EACCES/);
      expect(fs.readFileSync(target, "utf8")).toBe(prior);
      expect(fs.lstatSync(path.join(dir, "corb.sum")).isSymbolicLink()).toBe(true);
      expect(fs.readdirSync(store)).toEqual(["pins.toml"]);
    } finally {
      fs.chmodSync(store, 0o700);
    }
  });
  it("keeps the old target when the atomic rename fails and cleans its temporary file", () => {
    const dir = temporary();
    const file = path.join(dir, "corb.sum");
    const prior = serializeLayerLock({ version: 1, target: { x86_64: pins() } });
    fs.writeFileSync(file, prior);
    vi.spyOn(fs, "renameSync").mockImplementation(() => { throw new Error("rename denied"); });
    expect(() => refreshLayerPins(dir, "x86_64", pins())).toThrow("rename denied");
    expect(fs.readFileSync(file, "utf8")).toBe(prior);
    expect(fs.readdirSync(dir)).toEqual(["corb.sum"]);
  });
});

describe("immutable artifact references", () => {
  it.each([`ghcr.io/org/layer@sha256:${hash()}`, `localhost:5000/org/a_b.c--d@sha256:${hash()}`, `[::1]:5000/org/layer@sha256:${hash()}`])("accepts explicit digest reference %s", (value) => {
    expect(validateArtifactReference(value)).toBe(value);
  });
  it.each(["org/layer:latest", `org/layer@sha256:${hash()}`, `https://ghcr.io/org/layer@sha256:${hash()}`, `user@ghcr.io/org/layer@sha256:${hash()}`, `ghcr.io:0/org/layer@sha256:${hash()}`, `ghcr.io:65536/org/layer@sha256:${hash()}`, `ghcr.io/Org/layer@sha256:${hash()}`, `ghcr.io/org/../layer@sha256:${hash()}`, `ghcr.io/org/layer@sha256:${hash("A")}`, `ghcr.io/org/layer@sha256:${hash()}?q`])("rejects invalid reference %s", (value) => {
    expect(() => validateArtifactReference(value)).toThrow();
  });
});

it("binds only the selected target through a lockfile symlink", () => {
  const dir = temporary(); const target = path.join(dir, "real.sum"); const arm = pins(); arm.index = arm.index.map((row) => ({ ...row, url: row.url.replace("x86_64", "aarch64") }));
  fs.writeFileSync(target, serializeLayerLock({ version: 1, target: { x86_64: pins(), aarch64: arm } })); fs.symlinkSync("real.sum", path.join(dir, "corb.sum")); const artifact = `registry.example/team/input@sha256:${hash()}`;
  bindLayerArtifact(dir, "x86_64", pins(), artifact);
  expect(readLayerLock(dir)?.target).toEqual({ x86_64: { ...pins(), artifact }, aarch64: arm }); expect(fs.lstatSync(path.join(dir, "corb.sum")).isSymbolicLink()).toBe(true); expect(fs.statSync(target).mode & 0o777).toBe(0o600);
});
it("preserves the old lock after a selected-pin mismatch during artifact binding", () => {
  const dir = temporary(); const file = path.join(dir, "corb.sum"); const before = serializeLayerLock({ version: 1, target: { x86_64: pins() } }); fs.writeFileSync(file, before);
  expect(() => bindLayerArtifact(dir, "x86_64", { ...pins(), "definition-sha256": hash("9") }, `registry.example/team/input@sha256:${hash()}`)).toThrow("pins changed"); expect(fs.readFileSync(file, "utf8")).toBe(before);
});
