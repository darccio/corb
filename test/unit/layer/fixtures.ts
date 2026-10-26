import { hashLayerDefinition, normalizeLayerDefinition } from "../../../src/layer/definition.ts";
import type { LayerTargetPins } from "../../../src/layer/pins.ts";

export const hash = (byte = "a") => byte.repeat(64);
export const checksum = `Q1${Buffer.alloc(20).toString("base64")}`;
export function definition() { return normalizeLayerDefinition({ packages: ["go"] }); }
export function pins(): LayerTargetPins {
  return { os: "linux", abi: "musl", "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition()),
    index: ["main", "community"].map((repo, i) => ({ repository: repo as "main" | "community", url: `https://dl-cdn.alpinelinux.org/alpine/v3.23/${repo}/x86_64/APKINDEX.tar.gz`, sha256: hash(i === 0 ? "b" : "c") })),
    installer: { name: "apk-tools-static", version: "3.0.0-r0", repository: "main", "apkindex-checksum": checksum, "archive-sha256": hash("d") },
    package: [ { name: "go", version: "1.26.0-r0", repository: "community", "apkindex-checksum": checksum, "archive-sha256": hash("e"), requested: true },
      { name: "musl", version: "1.2.5-r0", repository: "main", "apkindex-checksum": checksum, "archive-sha256": hash("f"), requested: false } ] };
}
export function payload() { return { name: "go", url: "https://go.dev/dl/go1.26.0.linux-amd64.tar.gz", sha256: hash(), arch: "x86_64", destination: "/opt/corb/toolchains/go", "strip-components": 1, path: ["bin"] }; }
