// Unit tests for `src/config/render.ts` — M2.5. Covers: text output
// contains the key sections and a visible trust verdict, JSON output
// round-trips through `JSON.parse` to something matching the resolved data,
// and a widening diff is visible in both formats.
import { describe, expect, it } from "vitest";
import type { EffectiveConfig } from "../../../src/config/load.ts";
import type { ResolvedWorkspace } from "../../../src/config/resolve.ts";
import { renderJson, renderText } from "../../../src/config/render.ts";
import { builtinGitRules } from "../../../src/config/gitprotect.ts";

describe("config/render: workspace sources", () => {
  function workspaceWithSources(): ResolvedWorkspace {
    const resolved = noChangeWorkspace();
    const entry = {
      name: "bad name", dir: "/personal/bad name", realPath: "/personal/bad name", corbToml: "/personal/bad name/corb.toml",
      source: 1, valid: false, reason: "invalid workspace name", replaced: [{ source: 0, dir: "/shared/bad name" }],
    };
    resolved.workspaces = {
      sources: [
        { raw: "~/shared", path: "/home/user/shared", realPath: "/shared", exists: true },
        { raw: "/personal", path: "/personal", realPath: "/personal", exists: true },
        { raw: "/missing", path: "/missing", realPath: "/missing", exists: false },
      ],
      workspaces: [entry], allWorkspaces: [entry],
    };
    return resolved;
  }

  it("shows ordered sources, missing paths, invalid names and replaced copies before trust", () => {
    const text = renderText(workspaceWithSources());
    expect(text).toContain("source 0: raw=~/shared resolved=/shared");
    expect(text).toContain("source 2: raw=/missing resolved=/missing missing");
    expect(text).toContain("bad name: source=1 dir=/personal/bad name");
    expect(text).toContain("invalid: invalid workspace name");
    expect(text).toContain("replaces /shared/bad name (source=0)");
    expect(text.indexOf("audit:")).toBeLessThan(text.indexOf("workspaces:"));
    expect(text.indexOf("workspaces:")).toBeLessThan(text.indexOf("trust:"));
  });

  it("includes the complete listing in JSON without modifying the effective config", () => {
    const resolved = workspaceWithSources();
    expect(JSON.parse(renderJson(resolved)).workspaces).toEqual(resolved.workspaces);
    expect(JSON.parse(renderJson(resolved)).config).not.toHaveProperty("workspaces");
  });
});

function baseConfig(): EffectiveConfig {
  return {
    version: 1,
    name: "corb-dev",
    vm: { image: "corb:0.1.0", memory: "4G", cpus: 2 },
    agent: { provider: "anthropic", model: "claude-opus-4-5" },
    secrets: { ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] } },
    egress: {
      allow: ["api.anthropic.com"],
      "allow-internal": [],
      "block-internal-ranges": true,
      websockets: false,
    },
    git: { "ssh-agent": true, "allow-push": false },
    dir: [{ name: "myproj", host: "/home/user/myproj", mode: "rw", "builtin-rules": builtinGitRules(), rules: [] }],
    policy: { enabled: true, "secret-scan": true, "fail-open": true },
  };
}

function noChangeWorkspace(): ResolvedWorkspace {
  const config = baseConfig();
  return {
    dir: "/home/user/myproj",
    primary: "myproj",
    selectedWorkspace: undefined,
    positionalDirAdded: true,
    persistentConfig: config,
    fullConfig: config,
    trustKey: "/home/user/myproj",
    priorRecord: undefined,
    impliedHosts: [],
    workspaces: { sources: [], workspaces: [], allWorkspaces: [] },
    trustEvaluation: { verdict: "trusted", widened: [], narrowed: [] },
  };
}

function wideningWorkspace(): ResolvedWorkspace {
  const persistentConfig = baseConfig();
  const fullConfig = baseConfig();
  fullConfig.egress.allow = ["api.anthropic.com", "example.com"];
  return {
    dir: "/home/user/myproj",
    primary: "myproj",
    selectedWorkspace: undefined,
    positionalDirAdded: true,
    persistentConfig,
    fullConfig,
    trustKey: "/home/user/myproj",
    priorRecord: undefined,
    impliedHosts: [],
    workspaces: { sources: [], workspaces: [], allWorkspaces: [] },
    trustEvaluation: {
      verdict: "requires-confirmation",
      widened: [{ field: "egress.allow", description: "egress.allow gained 'example.com'" }],
      narrowed: [],
    },
  };
}

/** A workspace whose `fullConfig` has a CLI-added dir the (persistent-only) trust evaluation knows nothing about. */
function cliAddedDirWorkspace(): ResolvedWorkspace {
  const persistentConfig = baseConfig();
  const fullConfig = baseConfig();
  fullConfig.dir = [...persistentConfig.dir, { name: "extra", host: "/tmp/extra", mode: "ro", "builtin-rules": [], rules: [] }];
  return {
    dir: "/home/user/myproj",
    primary: "myproj",
    selectedWorkspace: undefined,
    positionalDirAdded: true,
    persistentConfig,
    fullConfig,
    trustKey: "/home/user/myproj",
    priorRecord: undefined,
    impliedHosts: [],
    workspaces: { sources: [], workspaces: [], allWorkspaces: [] },
    trustEvaluation: { verdict: "trusted", widened: [], narrowed: [] },
  };
}

describe("config/render: renderText", () => {
  it("shows built-in Git rules separately from user rules", () => {
    const workspace = noChangeWorkspace();
    workspace.fullConfig.dir[0]!.rules = [{ glob: "frozen.txt", mode: "deny-write" }];
    const text = renderText(workspace);
    expect(text).toContain("builtin rules (protect-git):");
    expect(text).toContain("glob=.git mode=deny-write reason=protect host Git metadata");
    expect(text).toMatch(/builtin rules \(protect-git\):[\s\S]+rules:\n\s+- glob=frozen.txt/);
    const json = JSON.parse(renderJson(workspace));
    expect(json.config.dir[0]["builtin-rules"]).toEqual(builtinGitRules());
    expect(json.config.dir[0].rules).toEqual([{ glob: "frozen.txt", mode: "deny-write" }]);
  });

  it("shows when a directory has no built-in Git rules", () => {
    expect(renderText(cliAddedDirWorkspace())).toContain("builtin rules (protect-git): (none)");
  });

  it("contains the key config sections and a visible trust verdict for a no-change workspace", () => {
    const text = renderText(noChangeWorkspace());
    expect(text).toContain("directory: /home/user/myproj");
    expect(text).toContain("vm:");
    expect(text).toContain("corb:0.1.0");
    expect(text).toContain("agent:");
    expect(text).toContain("secrets:");
    expect(text).toContain("ANTHROPIC_API_KEY");
    expect(text).toContain("egress:");
    expect(text).toContain("git:");
    expect(text).toContain("dir:");
    expect(text).toContain("myproj");
    expect(text).toContain("policy:");
    expect(text).toContain("trust:");
    expect(text).toContain("verdict: TRUSTED");
  });

  it("says a host-brokered provider logs in with corb login, and stays silent for API-key providers", () => {
    expect(renderText(noChangeWorkspace())).not.toContain("login:");
    const workspace = noChangeWorkspace();
    const config: EffectiveConfig = { ...workspace.fullConfig, agent: { provider: "openai-codex" } };
    const text = renderText({ ...workspace, persistentConfig: config, fullConfig: config });
    expect(text).toContain("  login: host-brokered, see 'corb login openai-codex' (allows chatgpt.com automatically)");
  });

  it("shows implied hosts and their source directly after allow", () => {
    const workspace = noChangeWorkspace();
    workspace.fullConfig.egress.allow = ["api.anthropic.com", "chatgpt.com"];
    workspace.impliedHosts = [{ host: "chatgpt.com", source: { kind: "agent-provider", provider: "openai-codex", layer: "global" } }];
    expect(renderText(workspace)).toContain(
      '  allow: [api.anthropic.com, chatgpt.com]\n  implied:\n    - chatgpt.com (implied by [agent] provider = "openai-codex")\n  allow-internal:',
    );
    expect(renderText(noChangeWorkspace())).not.toContain("  implied:");
  });

  it("never prints a secret value, only the secret's name and host-binding metadata", () => {
    const text = renderText(noChangeWorkspace());
    // Only 'hosts'/'optional' metadata should appear next to the secret name — no room for a value field to leak, since EffectiveConfig itself never carries one.
    expect(text).toMatch(/ANTHROPIC_API_KEY: hosts=\[api\.anthropic\.com\] optional=\(unset\)/);
  });

  it("shows '(unset)' for a secret with no [secrets.NAME.verify] configured", () => {
    const text = renderText(noChangeWorkspace());
    expect(text).toMatch(/ANTHROPIC_API_KEY:.*\n\s*verify: \(unset\)/);
  });

  it("shows a configured [secrets.NAME.verify]'s url/header/expect-status, never the secret's own value", () => {
    const config = baseConfig();
    config.secrets = {
      ANTHROPIC_API_KEY: {
        hosts: ["api.anthropic.com"],
        verify: { url: "https://api.anthropic.com/v1/models", header: "x-api-key", "expect-status": [200] },
      },
    };
    const workspace: ResolvedWorkspace = {
      dir: "/home/user/myproj",
      primary: "myproj",
      selectedWorkspace: undefined,
      positionalDirAdded: true,
      persistentConfig: config,
      fullConfig: config,
      trustKey: "/home/user/myproj",
      priorRecord: undefined,
      impliedHosts: [],
      workspaces: { sources: [], workspaces: [], allWorkspaces: [] },
      trustEvaluation: { verdict: "trusted", widened: [], narrowed: [] },
    };
    const text = renderText(workspace);
    expect(text).toContain("verify: url=https://api.anthropic.com/v1/models header=x-api-key header-prefix=(unset) expect-status=[200]");
  });

  it("shows a configured [secrets.NAME.verify]'s header-prefix", () => {
    const config = baseConfig();
    config.secrets = {
      OPENROUTER_API_KEY: {
        hosts: ["openrouter.ai"],
        verify: { url: "https://openrouter.ai/api/v1/models", header: "Authorization", "header-prefix": "Bearer " },
      },
    };
    const workspace: ResolvedWorkspace = {
      dir: "/home/user/myproj",
      primary: "myproj",
      selectedWorkspace: undefined,
      positionalDirAdded: true,
      persistentConfig: config,
      fullConfig: config,
      trustKey: "/home/user/myproj",
      priorRecord: undefined,
      impliedHosts: [],
      workspaces: { sources: [], workspaces: [], allWorkspaces: [] },
      trustEvaluation: { verdict: "trusted", widened: [], narrowed: [] },
    };
    const text = renderText(workspace);
    expect(text).toContain("header-prefix=Bearer ");
  });

  it("makes a widening diff visible: verdict and itemized widened change both appear", () => {
    const text = renderText(wideningWorkspace());
    expect(text).toContain("verdict: REQUIRES-CONFIRMATION");
    expect(text).toContain("widened");
    expect(text).toContain("egress.allow gained 'example.com'");
  });

  it("describes fullConfig (what will actually run), including CLI-added directories", () => {
    const text = renderText(cliAddedDirWorkspace());
    expect(text).toContain("myproj");
    expect(text).toContain("extra");
    expect(text).toContain("/tmp/extra");
  });

  it("the trust section states its scope and does not claim to cover CLI-added directories, even though one is present in fullConfig", () => {
    const text = renderText(cliAddedDirWorkspace());
    expect(text).toContain("verdict: TRUSTED");
    expect(text).toContain("scope: config.toml + positional directory /home/user/myproj");
  });

  it("shows github-api as (unset) when no [egress.github-api] table is configured at all", () => {
    const text = renderText(noChangeWorkspace());
    expect(text).toContain("github-api: (unset)");
  });

  it("makes an unset github-api.hosts' live default (api.github.com) visible, not just '(unset)'", () => {
    // A workspace enforcement gap this project cares about (`docs/design.md`
    // "policy you can't read is policy you won't trust"): `src/policy/github.ts`
    // defaults an unset `hosts` to `api.github.com` at enforcement time, so a
    // bare "(unset)" here would misleadingly read as "nothing is being
    // gated", when a `methods`/`deny-paths` restriction is actually live
    // against that default host.
    const workspace = noChangeWorkspace();
    workspace.fullConfig.egress["github-api"] = { methods: ["GET", "POST", "PATCH"] };
    const text = renderText(workspace);
    expect(text).toContain("hosts: (unset, defaults to api.github.com)");
    expect(text).toContain("methods: [GET, POST, PATCH]");
  });

  it("shows an explicitly configured github-api.hosts verbatim, not the default", () => {
    const workspace = noChangeWorkspace();
    workspace.fullConfig.egress["github-api"] = { hosts: ["ghes.example.com"] };
    const text = renderText(workspace);
    expect(text).toContain("hosts: [ghes.example.com]");
    expect(text).not.toContain("api.github.com");
  });

  it("makes an unset github-api.methods' live default ([GET, HEAD]) visible, not just '(unset)'", () => {
    // Same enforcement gap as the `hosts` case above, but for `methods`:
    // `src/policy/github.ts`'s `githubApiGate` defaults an unset `methods`
    // to `["GET", "HEAD"]` at enforcement time (fail-closed), so a bare
    // "(unset)" here would misleadingly read as "every method is allowed",
    // when in fact only GET/HEAD pass through.
    const workspace = noChangeWorkspace();
    workspace.fullConfig.egress["github-api"] = { hosts: ["ghes.example.com"] };
    const text = renderText(workspace);
    expect(text).toContain("methods: (unset, defaults to [GET, HEAD])");
  });

  it("shows an explicitly configured github-api.methods verbatim, not the default", () => {
    const workspace = noChangeWorkspace();
    workspace.fullConfig.egress["github-api"] = { methods: ["GET", "POST", "PATCH"] };
    const text = renderText(workspace);
    expect(text).toContain("methods: [GET, POST, PATCH]");
    expect(text).not.toContain("defaults to [GET, HEAD]");
  });
});

describe("config/render: renderJson", () => {
  it("round-trips through JSON.parse to data matching the resolved workspace", () => {
    const resolved = noChangeWorkspace();
    const json = renderJson(resolved);
    const parsed = JSON.parse(json);
    expect(parsed).toEqual({
      dir: resolved.dir,
      primary: resolved.primary,
      selectedWorkspace: null,
      trustKey: resolved.trustKey,
      config: resolved.fullConfig,
      impliedHosts: [],
      trust: resolved.trustEvaluation,
      workspaces: resolved.workspaces,
    });
  });

  it("includes implied-host source metadata beside the effective config", () => {
    const resolved = noChangeWorkspace();
    resolved.fullConfig.egress.allow = ["chatgpt.com"];
    resolved.impliedHosts = [{ host: "chatgpt.com", source: { kind: "agent-provider", provider: "openai-codex", layer: "global" } }];
    const parsed = JSON.parse(renderJson(resolved));
    expect(parsed.impliedHosts).toEqual(resolved.impliedHosts);
    expect(parsed.config.egress.allow).toEqual(["chatgpt.com"]);
    expect(parsed.config).not.toHaveProperty("impliedHosts");
  });

  it("is pretty-printed (indented), not minified", () => {
    const json = renderJson(noChangeWorkspace());
    expect(json).toContain("\n");
    expect(json).toContain("  ");
  });

  it("makes a widening diff visible in the JSON output", () => {
    const json = renderJson(wideningWorkspace());
    const parsed = JSON.parse(json);
    expect(parsed.trust.verdict).toBe("requires-confirmation");
    expect(parsed.trust.widened).toEqual([{ field: "egress.allow", description: "egress.allow gained 'example.com'" }]);
  });
});

describe("config/render: selected workspace metadata", () => {
  it.each(["name", "path"] as const)("shows selection by %s in text and JSON", (selectedBy) => {
    const resolved = noChangeWorkspace();
    resolved.selectedWorkspace = { name: "team", selectedBy, source: { index: 0, raw: "~/corbfiles", path: "/home/user/corbfiles" }, dir: "/home/user/corbfiles/team", corbToml: "/home/user/corbfiles/team/corb.toml" };
    resolved.positionalDirAdded = selectedBy === "name";
    resolved.workspaces.projectsRoot = "/home/user/projects";
    resolved.trustKey = "workspace:team:/home/user/myproj";
    const text = renderText(resolved);
    expect(text).toContain(`workspace: team (selected by ${selectedBy}; source ~/corbfiles; /home/user/corbfiles/team)`);
    expect(text).toContain("primary: myproj");
    expect(text).toContain("projects-root: /home/user/projects");
    expect(text).toContain("key: workspace:team:/home/user/myproj");
    expect(text).toContain("scope: config.toml + workspace team corb.toml");
    if (selectedBy === "name") expect(text).toContain("+ positional directory /home/user/myproj");
    else expect(text).not.toContain("+ positional directory");
    const json = JSON.parse(renderJson(resolved));
    expect(json.selectedWorkspace).toEqual(resolved.selectedWorkspace);
    expect(json.primary).toBe("myproj");
    expect(json.workspaces.projectsRoot).toBe("/home/user/projects");
  });

  it("shows a nullable DIR when name selection adds no positional mount", () => {
    const resolved = noChangeWorkspace();
    resolved.dir = undefined;
    resolved.positionalDirAdded = false;
    resolved.selectedWorkspace = { name: "team", selectedBy: "name", source: { index: 0, raw: "/definitions", path: "/definitions" }, dir: "/definitions/team", corbToml: "/definitions/team/corb.toml" };
    expect(renderText(resolved)).toContain("directory: (none)");
    expect(renderText(resolved)).not.toContain("+ positional directory");
    expect(JSON.parse(renderJson(resolved)).dir).toBeNull();
  });

  it("shows global-only selection explicitly", () => {
    const resolved = noChangeWorkspace();
    expect(renderText(resolved)).toContain("workspace: (none; global config only)");
    expect(JSON.parse(renderJson(resolved)).selectedWorkspace).toBeNull();
  });
});
