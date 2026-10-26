import { describe, expect, it } from "vitest";
import { validateSdkArchiveEntries, type SdkArchiveEntry } from "../../../src/layer/archive.ts";
import { normalizeLayerDefinition } from "../../../src/layer/definition.ts";
import { payload } from "./fixtures.ts";

const sdk = () => normalizeLayerDefinition({ packages: [], payload: [payload()] }).payload[0]!;
const file = (path = "go/bin/go"): SdkArchiveEntry => ({ path, type: "file", mode: 0o755, size: 10 });

describe("SDK archive header validation", () => {
  it("strips the archive prefix and normalizes readable immutable modes", () => {
    expect(validateSdkArchiveEntries([{ ...file("go/"), type: "directory", size: 0 }, { ...file("go/bin"), type: "directory", size: 0 }, file(), { ...file("go/README"), mode: 0o600 }], sdk())).toEqual([
      { path: "bin", type: "directory", mode: 0o555, size: 0 }, { path: "bin/go", type: "file", mode: 0o555, size: 10 }, { path: "README", type: "file", mode: 0o444, size: 10 },
    ]);
  });
  it.each(["symlink", "hardlink", "device", "socket", "fifo"])("rejects special file type %s", (type) => {
    expect(() => validateSdkArchiveEntries([{ ...file(), type }], sdk())).toThrow("forbids");
  });
  it.each(["/etc/passwd", "go/../escape", "go/./bin", "go//bin", "go/\\bin", "go/bin\0x"])("rejects path %j", (path) => {
    expect(() => validateSdkArchiveEntries([file(path)], sdk())).toThrow();
  });
  it("validates extended-header paths before stripping", () => {
    expect(() => validateSdkArchiveEntries([{ ...file(), pax: { path: "../../escape" } }], sdk())).toThrow();
    expect(validateSdkArchiveEntries([{ ...file(), pax: { path: "go/bin/renamed" } }], sdk())[0]?.path).toBe("bin/renamed");
  });
  it("rejects duplicate final paths and file ancestors in either order", () => {
    expect(() => validateSdkArchiveEntries([file(), file()], sdk())).toThrow("duplicate");
    const directory = { ...file("go/"), type: "directory", size: 0 };
    expect(() => validateSdkArchiveEntries([directory, directory], sdk())).toThrow("duplicate");
    for (const entries of [[file("go/bin"), file()], [file(), file("go/bin")]]) expect(() => validateSdkArchiveEntries(entries, sdk())).toThrow("ancestor");
  });
  it.each([{ mode: 0o4755 }, { pax: { "SCHILY.xattr.security.capability": "x" } }, { pax: { "GNU.sparse.size": "2" } }, { pax: { size: "11" } }])("rejects special permission and metadata %j", (change) => {
    expect(() => validateSdkArchiveEntries([{ ...file(), ...change }], sdk())).toThrow();
  });
  it("enforces expansion, entry and UTF-8 path byte bounds", () => {
    expect(() => validateSdkArchiveEntries([{ ...file(), size: 2 * 1024 ** 3 }, { ...file("go/bin/other"), size: 1 }], sdk())).toThrow("2 GiB");
    expect(() => validateSdkArchiveEntries(Array(100001).fill(file()), sdk())).toThrow("100000");
    expect(() => validateSdkArchiveEntries([file(`go/${"é".repeat(2049)}`)], sdk())).toThrow("4096");
  });
});
