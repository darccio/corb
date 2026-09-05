// Unit tests for `src/commands/image.ts`. `imageBuild()` itself does real
// Docker/VM work and stays untested at the unit level. This file covers
// only the arch-placeholder-substitution helpers, which are pure and
// synchronous: `GOARCH_BY_IMAGE_ARCH` (the ImageArch -> Go GOARCH naming
// map) and `resolveArchPlaceholders` (substituting the `{arch}` token in
// `postBuild.copy[].src`, as used by corb-image.json's guest-binary
// entries).
import { describe, expect, it } from "vitest";
import { GOARCH_BY_IMAGE_ARCH, resolveArchPlaceholders } from "../../../src/commands/image.ts";

describe("commands/image: GOARCH_BY_IMAGE_ARCH", () => {
  it("maps both ImageArch values to the Go GOARCH string the Makefile's guest-<GOARCH> targets produce", () => {
    expect(GOARCH_BY_IMAGE_ARCH.x86_64).toBe("amd64");
    expect(GOARCH_BY_IMAGE_ARCH.aarch64).toBe("arm64");
  });
});

describe("commands/image: resolveArchPlaceholders", () => {
  it("substitutes {arch} with amd64 for x86_64", () => {
    const raw: Record<string, unknown> = {
      postBuild: {
        copy: [{ src: "../guest/build/{arch}/dropcap", dest: "/usr/local/bin/dropcap" }],
      },
    };
    resolveArchPlaceholders(raw, "x86_64");
    const copy = (raw.postBuild as { copy: { src: string }[] }).copy;
    expect(copy[0].src).toBe("../guest/build/amd64/dropcap");
  });

  it("substitutes {arch} with arm64 for aarch64", () => {
    const raw: Record<string, unknown> = {
      postBuild: {
        copy: [{ src: "../guest/build/{arch}/policygate", dest: "/usr/local/libexec/policygate" }],
      },
    };
    resolveArchPlaceholders(raw, "aarch64");
    const copy = (raw.postBuild as { copy: { src: string }[] }).copy;
    expect(copy[0].src).toBe("../guest/build/arm64/policygate");
  });

  it("leaves a src with no {arch} placeholder untouched", () => {
    const raw: Record<string, unknown> = {
      postBuild: {
        copy: [{ src: "overlay/etc/corb/suid-allowlist.txt", dest: "/etc/corb/suid-allowlist.txt" }],
      },
    };
    resolveArchPlaceholders(raw, "x86_64");
    const copy = (raw.postBuild as { copy: { src: string }[] }).copy;
    expect(copy[0].src).toBe("overlay/etc/corb/suid-allowlist.txt");
  });

  it("handles multiple copy entries independently, including a mix of placeholder and non-placeholder entries", () => {
    const raw: Record<string, unknown> = {
      postBuild: {
        copy: [
          { src: "../guest/build/{arch}/dropcap", dest: "/usr/local/bin/dropcap" },
          { src: "../guest/build/{arch}/policygate", dest: "/usr/local/libexec/policygate" },
          { src: "overlay/etc/corb/image.json", dest: "/etc/corb/image.json" },
        ],
      },
    };
    resolveArchPlaceholders(raw, "aarch64");
    const copy = (raw.postBuild as { copy: { src: string }[] }).copy;
    expect(copy[0].src).toBe("../guest/build/arm64/dropcap");
    expect(copy[1].src).toBe("../guest/build/arm64/policygate");
    expect(copy[2].src).toBe("overlay/etc/corb/image.json");
  });
});
