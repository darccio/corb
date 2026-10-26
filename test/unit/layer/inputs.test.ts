import { describe, expect, it } from "vitest";
import { expectedInputBlobs, normalizeInputConfig, serializeInputConfig, serializeInputManifest, validateInputArtifact } from "../../../src/layer/inputs.ts";
import { TITLE } from "../../../src/layer/metadata.ts";
import { hashLayerDefinition, normalizeLayerDefinition } from "../../../src/layer/definition.ts";
import { sha256 } from "../../../src/layer/validate.ts";
import { definition, hash, payload, pins } from "./fixtures.ts";

function fixture() {
  const config = { version: 1 as const, definition: definition(), pins: pins() };
  const sizes = new Map(expectedInputBlobs(config).map((input) => [`sha256:${input.sha256}`, 10]));
  const bytes = serializeInputConfig(config, "x86_64");
  const root = serializeInputManifest(config, "x86_64", sizes);
  return { config, sizes, bytes, root };
}

describe("input artifact contracts", () => {
  it("orders exact signed indexes, installer and full candidate closure", () => {
    const { config, sizes, root, bytes } = fixture();
    const result = validateInputArtifact(root, bytes, "x86_64", sizes);
    expect(result.manifest.layers.map((item) => item.annotations[TITLE])).toEqual(["index/main", "index/community", "installer", "package/go", "package/musl"]);
    expect(result.config).toEqual(config);
    expect(serializeInputConfig(config, "x86_64")).toBe(bytes);
  });
  it("includes SDK archives in preserved definition order", () => {
    const layer = normalizeLayerDefinition({ packages: [], payload: [{ ...payload(), name: "z", destination: "/opt/corb/toolchains/z" }, payload()] });
    const config = { version: 1 as const, definition: layer, pins: { ...pins(), index: [], installer: undefined, package: [], "definition-sha256": hashLayerDefinition(layer) } };
    expect(expectedInputBlobs(config).map((input) => input.role)).toEqual(["payload/z", "payload/go"]);
  });
  it.each([
    (root: any) => { root.subject = root.config; },
    (root: any) => { root.mediaType = "application/vnd.oci.image.index.v1+json"; },
    (root: any) => { root.artifactType = "application/vnd.corb.base.v1"; },
    (root: any) => { root.schemaVersion = 1; },
    (root: any) => { root.config.urls = ["https://example.com"]; },
    (root: any) => { root.layers[0].urls = ["https://example.com"]; },
    (root: any) => { root.layers[0].mediaType = "application/octet-stream"; },
    (root: any) => { root.layers[0].digest = `sha512:${hash()}`; },
    (root: any) => { root.layers[0].size = -1; },
    (root: any) => { root.layers[0].size = 11; },
    (root: any) => { root.layers[0].annotations[TITLE] = "../main"; },
    (root: any) => { root.layers[0].annotations[TITLE] = "/index/main"; },
    (root: any) => { root.layers[0].annotations.extra = "ignored"; },
    (root: any) => { root.layers[1] = root.layers[0]; },
    (root: any) => { root.layers.reverse(); },
    (root: any) => { root.layers.pop(); },
    (root: any) => { root.layers.push(root.layers[0]); },
    (root: any) => { root.layers[0].digest = `sha256:${hash()}`; },
    (root: any) => { root.config.size++; },
  ])("rejects unsafe or mismatched manifest mutation %#", (mutate) => {
    const { root, bytes, sizes } = fixture();
    const changed = JSON.parse(root);
    mutate(changed);
    expect(() => validateInputArtifact(JSON.stringify(changed), bytes, "x86_64", sizes)).toThrow();
  });
  it("rejects unsupported, mismatched, self-referential and unnormalized configs", () => {
    const { config } = fixture();
    for (const changed of [ { ...config, version: 2 }, { ...config, unknown: true },
      { ...config, pins: { ...pins(), artifact: `ghcr.io/org/layer@sha256:${hash()}` } },
      { ...config, pins: { ...pins(), "definition-sha256": hash() } },
      { ...config, definition: { packages: ["go"] } },
    ]) expect(() => normalizeInputConfig(changed, "x86_64")).toThrow();
  });
  it("rejects duplicate JSON keys and invalid UTF-8", () => {
    const { root, bytes, sizes } = fixture();
    expect(() => validateInputArtifact(root.replace('"schemaVersion":2', '"schemaVersion":2,"schemaVersion":2'), bytes, "x86_64", sizes)).toThrow("duplicate JSON key");
    expect(() => validateInputArtifact(root, new Uint8Array([255]), "x86_64", sizes)).toThrow("UTF-8");
  });
  it("bounds metadata, descriptors and individual blobs", () => {
    const { root, bytes, sizes } = fixture();
    expect(() => validateInputArtifact(" ".repeat(1024 * 1024 + 1), bytes, "x86_64", sizes)).toThrow("1 MiB");
    expect(() => validateInputArtifact(root, " ".repeat(1024 * 1024 + 1), "x86_64", sizes)).toThrow("1 MiB");
    const changed = JSON.parse(root);
    changed.layers[0].size = 512 * 1024 ** 2 + 1;
    expect(() => validateInputArtifact(JSON.stringify(changed), bytes, "x86_64", sizes)).toThrow();
    changed.layers = Array(1025).fill(changed.layers[0]);
    expect(() => validateInputArtifact(JSON.stringify(changed), bytes, "x86_64", sizes)).toThrow();
  });
  it("rejects graph sizes above 32 GiB even when every blob meets its bound", () => {
    const { config } = fixture();
    config.pins.package.push(...Array.from({ length: 64 }, (_, i) => ({ ...pins().package[1]!, name: `lib${String(i).padStart(2, "0")}`, "archive-sha256": sha256(String(i)) })));
    config.pins.package.sort((a, b) => a.name.localeCompare(b.name));
    const sizes = new Map(expectedInputBlobs(config).map((input) => [`sha256:${input.sha256}`, 512 * 1024 ** 2]));
    expect(() => serializeInputManifest(config, "x86_64", sizes)).toThrow("32 GiB");
  });
});
