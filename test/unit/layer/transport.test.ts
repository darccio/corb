import { expect, it } from "vitest";
import { inspectArtifactRoot, registryFlags, validatePushDestination } from "../../../src/layer/transport.ts";
import { serializeInputConfig, serializeInputManifest } from "../../../src/layer/inputs.ts";
import { normalizeLayerDefinition, hashLayerDefinition } from "../../../src/layer/definition.ts";
import { sha256 } from "../../../src/layer/validate.ts";
function root() {
  const definition = normalizeLayerDefinition({ packages: [], commands: ["true"] });
  const config = { version: 1 as const, definition, pins: { os: "linux" as const, abi: "musl" as const, "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition), index: [], package: [] } };
  return Buffer.from(serializeInputManifest(config, "x86_64", new Map()));
}
it.each(["repo:tag", "org/repo:tag", "ghcr.io/org/repo", "ghcr.io/org/repo@sha256:" + "a".repeat(64), "https://ghcr.io/org/repo:tag", "ghcr.io/UPPER/repo:tag"])("rejects unqualified destination %s", (value) => { expect(() => validatePushDestination(value)).toThrow(); });
it.each(["ghcr.io/org/repo:tag", "localhost:5443/test:tag", "registry.example:443/group/repo:tag"])("accepts an explicit tagged destination %s", (value) => { expect(validatePushDestination(value)).toBe(value); });
it("passes only verified TLS/auth options through each ORAS interface", () => {
  expect(registryFlags({ registryConfig: "/private/auth", caFile: "/private/ca" }, "from")).toEqual(["--from-plain-http=false", "--from-registry-config", "/private/auth", "--from-ca-file", "/private/ca"]);
  expect(registryFlags({})).toEqual(["--plain-http=false"]);
  expect(registryFlags({}, "to")).toEqual(["--to-plain-http=false"]);
});
it("rejects a base artifact as an input artifact and rejects external URL/subject edges", () => {
  const bytes = root(); const digest = `sha256:${sha256(bytes)}`; expect(inspectArtifactRoot(bytes, "input", digest).artifactType).toContain("layer-inputs");
  expect(() => inspectArtifactRoot(bytes, "base", digest)).toThrow("type");
  for (const field of ["subject", "urls"]) { const candidate = Buffer.from(JSON.stringify({ ...JSON.parse(bytes.toString()), [field]: {} })); expect(() => inspectArtifactRoot(candidate, "input", `sha256:${sha256(candidate)}`)).toThrow("unknown key"); }
});
it("checks exact root digest before graph parsing", () => { expect(() => inspectArtifactRoot(root(), "input", `sha256:${"0".repeat(64)}`)).toThrow("digest"); });
