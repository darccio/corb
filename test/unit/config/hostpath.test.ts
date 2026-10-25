import { describe, expect, it } from "vitest";
import { resolveLayerHosts } from "../../../src/config/hostpath.ts";
import { ConfigParseError, type ConfigLayer } from "../../../src/config/schema.ts";

const options = { home: "/home/bec", sourceLabel: "workspace/corb.toml" };

describe("config/hostpath", () => {
  it.each([
    ["~", "/home/bec"], ["~/x", "/home/bec/x"],
    ["$HOME", "/home/bec"], ["$HOME/x", "/home/bec/x"], ["/absolute/x", "/absolute/x"],
  ])("expands %s to %s", (host, expected) => {
    expect(resolveLayerHosts({ dir: [{ name: "work", host }] }, options).dir?.[0].host).toBe(expected);
  });

  it("resolves relative hosts against projects-root", () => {
    expect(resolveLayerHosts({ dir: [{ name: "work", host: "repo/../other" }] }, { ...options, projectsRoot: "/projects" }).dir?.[0].host).toBe("/projects/other");
  });

  it("rejects relative hosts without projects-root with the file and field", () => {
    try {
      resolveLayerHosts({ dir: [{ name: "work", host: "relative" }] }, options);
      expect.fail("expected a host error");
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigParseError);
      expect(err).toMatchObject({ sourceLabel: options.sourceLabel, location: "dir[0].host" });
      expect(String(err)).toContain("[workspaces] projects-root");
      expect(String(err)).toContain("not resolved against the current directory");
    }
  });

  it.each(["~bob/x", "~bob", "${HOME}/x", "$HOMELESS/x", "$OTHER/x", ""])("rejects bad host %s", (host) => {
    expect(() => resolveLayerHosts({ dir: [{ name: "work", host }] }, options)).toThrow(ConfigParseError);
  });

  it("preserves future directory keys and host-less entries without mutating input", () => {
    const entry = { name: "work", host: "~/x", "protect-git": false, future: "kept", rules: [{ glob: "x", mode: "ro" as const }] };
    const layer: ConfigLayer = { name: "label", dir: [entry, { name: "hostless", create: true }] };
    const before = structuredClone(layer);
    const result = resolveLayerHosts(layer, options);
    expect(result).toEqual({ ...layer, dir: [{ ...entry, host: "/home/bec/x" }, { name: "hostless", create: true }] });
    expect(layer).toEqual(before);
    expect(result).not.toBe(layer);
    expect(result.dir).not.toBe(layer.dir);
    expect(result.dir?.[1]).not.toBe(layer.dir?.[1]);
  });

  it("keeps a layer without dirs unchanged in value", () => {
    expect(resolveLayerHosts({ name: "label" }, options)).toEqual({ name: "label" });
  });
});
