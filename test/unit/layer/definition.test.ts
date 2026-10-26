import { describe, expect, it } from "vitest";
import { assertLayerTarget, hashLayerDefinition, layerPayloadPath, normalizeLayerDefinition, serializeLayerDefinition } from "../../../src/layer/definition.ts";
import { parseConfigLayer } from "../../../src/config/schema.ts";
import { mergeConfigLayers } from "../../../src/config/load.ts";
import { payload } from "./fixtures.ts";

describe("workspace layer definition", () => {
  it.each(["[image]", "[image.layer]\npackages=['go']"])("rejects global image tables: %s", (text) => {
    expect(() => parseConfigLayer(text, "global")).toThrow("only allowed in a workspace");
  });
  it("rejects user pins and unknown layer fields", () => {
    for (const text of ["[image.pins]", "[image.layer]\npackages=['go']\nbase='x'"]) {
      expect(() => parseConfigLayer(text, "workspace", { scope: "workspace" })).toThrow("unknown key");
    }
  });
  it.each(["go>=1", "so:libc.musl", "https://example.com/go", "go.apk", "Go", "", "go@edge"])("rejects non P: names: %s", (name) => {
    expect(() => normalizeLayerDefinition({ packages: [name] })).toThrow();
  });
  it("requires packages even in command and payload recipes", () => {
    expect(() => normalizeLayerDefinition({ commands: ["true"] })).toThrow();
    expect(() => normalizeLayerDefinition({ packages: [] })).toThrow();
    expect(normalizeLayerDefinition({ packages: [], commands: ["true"] }).packages).toEqual([]);
    expect(normalizeLayerDefinition({ packages: [], payload: [payload()] }).packages).toEqual([]);
  });
  it("includes canonical defaults and set order, preserving command bytes", () => {
    const value = normalizeLayerDefinition({ packages: ["zlib", "go", "go"], commands: ["  echo a\n", "echo b"], hosts: ["z.dev", "A.dev", "z.dev"] });
    expect(serializeLayerDefinition(value)).toBe('{"packages":["go","zlib"],"commands":["  echo a\\n","echo b"],"build-hosts":["dl-cdn.alpinelinux.org"],"hosts":["a.dev","z.dev"],"payload":[],"runtime-dir":[]}');
    expect(hashLayerDefinition(value)).toBe(hashLayerDefinition(normalizeLayerDefinition({ ...value, packages: ["go", "zlib"] })));
    expect(normalizeLayerDefinition({ packages: ["go"], "build-hosts": [] })["build-hosts"]).toEqual([]);
  });
  it.each(["", "nul\0command"])("rejects malformed command %j", (command) => {
    expect(() => normalizeLayerDefinition({ packages: [], commands: [command] })).toThrow();
  });
  it.each(["https://a.dev", "a.dev/path", "a.dev:443", " a.dev", "a dev", "", ".a.dev", "a..dev"])("rejects hostname pattern %j", (host) => {
    expect(() => normalizeLayerDefinition({ packages: ["go"], hosts: [host] })).toThrow();
  });
  it("keeps existing wildcard matching shapes", () => {
    expect(normalizeLayerDefinition({ packages: ["go"], hosts: ["*", "*.example.com", "api*.example.com"] }).hosts).toEqual(["*", "*.example.com", "api*.example.com"]);
  });
  it.each([
    { name: "Go" }, { url: "http://go.dev/go.tar.gz" }, { url: "https://user:pass@go.dev/go.tar.gz" },
    { url: "https://go.dev/go.tar.gz?x" }, { url: "https://go.dev/go.zip" }, { sha256: "A".repeat(64) },
    { destination: "/opt/corb/toolchains/gopher" }, { destination: "/opt/corb/toolchains/go/../go" },
    { destination: "/opt/corb/toolchains/go//sdk" }, { "strip-components": 17 }, { "strip-components": -1 },
    { path: ["bin", "bin"] }, { path: ["../bin"] }, { path: ["/bin"] }, { path: ["bin/./tools"] }, { path: [""] },
    { arch: "amd64" }, { extra: true },
  ])("rejects unsafe payload %j", (change) => {
    expect(() => normalizeLayerDefinition({ packages: [], payload: [{ ...payload(), ...change }] })).toThrow();
  });
  it("preserves SDK and PATH order and reports architecture mismatch", () => {
    const first = { ...payload(), name: "z", destination: "/opt/corb/toolchains/z", path: ["tools", "bin"] };
    const definition = normalizeLayerDefinition({ packages: [], payload: [first, payload()] });
    expect(layerPayloadPath(definition)).toEqual(["/opt/corb/toolchains/z/tools", "/opt/corb/toolchains/z/bin", "/opt/corb/toolchains/go/bin"]);
    expect(() => assertLayerTarget(definition, "aarch64")).toThrow("incompatible with selected target");
    expect(() => normalizeLayerDefinition({ packages: [], payload: [payload(), payload()] })).toThrow("duplicate payload");
  });
  it.each(["/run", "/var/log", "/tmp/x", "/run/../tmp", "/run/corb", "/run/corb/x", "/run/gondolin", "/run//app", "/run/app/."])("rejects runtime path %s", (path) => {
    expect(() => normalizeLayerDefinition({ packages: ["go"], "runtime-dir": [{ path, owner: "root", group: "root" }] })).toThrow();
  });
  it.each([{ mode: "755" }, { mode: "1755" }, { owner: "1000" }, { group: "Root" }, { command: "start" }])("rejects runtime fields %j", (change) => {
    expect(() => normalizeLayerDefinition({ packages: ["go"], "runtime-dir": [{ path: "/run/app", owner: "root", group: "root", ...change }] })).toThrow();
  });
  it("normalizes runtime paths and rejects duplicates", () => {
    const runtime = [{ path: "/var/log/app", owner: "app", group: "app" }, { path: "/run/app", owner: "app", group: "app" }];
    expect(normalizeLayerDefinition({ packages: ["go"], "runtime-dir": runtime })["runtime-dir"].map((item) => [item.path, item.mode])).toEqual([["/run/app", "0755"], ["/var/log/app", "0755"]]);
    expect(() => normalizeLayerDefinition({ packages: ["go"], "runtime-dir": [runtime[0], runtime[0]] })).toThrow("duplicate");
  });
  it("replaces a whole recipe and returns independent objects", () => {
    const first = { image: { layer: normalizeLayerDefinition({ packages: ["go"] }) } };
    const next = { image: { layer: normalizeLayerDefinition({ packages: ["zlib"] }) } };
    const merged = mergeConfigLayers([first, next]);
    expect(merged.image?.layer.packages).toEqual(["zlib"]);
    merged.image!.layer.packages.push("bash");
    expect(next.image.layer.packages).toEqual(["zlib"]);
  });
});
