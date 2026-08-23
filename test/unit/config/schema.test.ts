// Unit tests for `src/config/schema.ts` — M2.1. Covers a full valid
// document round-tripping to the expected `ConfigLayer`, true partiality (a
// document with only `[[dir]]` entries), the `[secrets.NAME]` map-of-tables
// shape (arbitrary keys, fixed-shape values), and each rejected case: unknown
// keys at every level, invalid enum values, and malformed duration/size/
// percentage strings.
import { describe, expect, it } from "vitest";
import { ConfigParseError, parseConfigLayer } from "../../../src/config/schema.ts";

const FULL_VALID_TOML = `
version = 1
name    = "corb-dev"

[vm]
image = "corb:0.1.0"
memory = "4G"
cpus = 4
max-session = "4h"
limits = { memory-max = "6G", pids-max = 1024, cpu-quota = "400%" }

[agent]
provider = "anthropic"
model    = "claude-opus-4-5"
extensions = []
append-system-prompt-file = "~/.config/corb/APPEND_SYSTEM.md"

[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.GITHUB_TOKEN]
hosts = ["api.github.com"]
optional = true

[egress]
allow = ["api.anthropic.com", "api.github.com", "objects.githubusercontent.com",
         "codeload.github.com", "registry.npmjs.org", "proxy.golang.org", "sum.golang.org"]
allow-internal = []
block-internal-ranges = true
websockets = false

[egress.github-api]
hosts      = ["api.github.com"]
methods    = ["GET", "POST", "PATCH"]
deny-paths = ["**/actions/secrets/**", "**/actions/variables/**", "/user/keys**"]

[git]
ssh-agent   = true
allow-hosts = ["github.com"]
allow-repos = ["dario/corb", "dario/*-docs"]
allow-push  = false

[[dir]]
name  = "corb"
host  = "~/Code/corb"
mode  = "rw"
rules = [
  { glob = "**/*_test.go",  mode = "deny-write",   reason = "tests are frozen for this session" },
  { glob = "**/.env*",      mode = "hidden",       reason = "local secrets file" },
  { glob = "secrets/**",    mode = "hidden",       reason = "secrets directory" },
  { glob = ".git/hooks/**", mode = "shadow-write", reason = "keep hooks inert" },
  { glob = ".git/config",   mode = "deny-write",   reason = "no local git identity changes" },
]

[[dir]]
name = "reference"
host = "~/Code/reference-docs"
mode = "ro"

[[dir]]
name = "scratch"
host = "~/.cache/corb/scratch/corb-dev"
mode = "rw"
create = true

[policy]
enabled = true
secret-scan = true
max-changed-files = 40
fail-open = true

[audit]
path = "~/.local/state/corb/audit.jsonl"
`;

function expectConfigParseError(fn: () => unknown): ConfigParseError {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(ConfigParseError);
  return thrown as ConfigParseError;
}

describe("config/schema", () => {
  it("parses a full valid document into the expected ConfigLayer", () => {
    const layer = parseConfigLayer(FULL_VALID_TOML, "config.toml");

    expect(layer).toEqual({
      version: 1,
      name: "corb-dev",
      vm: {
        image: "corb:0.1.0",
        memory: "4G",
        cpus: 4,
        "max-session": "4h",
        limits: { "memory-max": "6G", "pids-max": 1024, "cpu-quota": "400%" },
      },
      agent: {
        provider: "anthropic",
        model: "claude-opus-4-5",
        extensions: [],
        "append-system-prompt-file": "~/.config/corb/APPEND_SYSTEM.md",
      },
      secrets: {
        ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
        GITHUB_TOKEN: { hosts: ["api.github.com"], optional: true },
      },
      egress: {
        allow: [
          "api.anthropic.com",
          "api.github.com",
          "objects.githubusercontent.com",
          "codeload.github.com",
          "registry.npmjs.org",
          "proxy.golang.org",
          "sum.golang.org",
        ],
        "allow-internal": [],
        "block-internal-ranges": true,
        websockets: false,
        "github-api": {
          hosts: ["api.github.com"],
          methods: ["GET", "POST", "PATCH"],
          "deny-paths": ["**/actions/secrets/**", "**/actions/variables/**", "/user/keys**"],
        },
      },
      git: {
        "ssh-agent": true,
        "allow-hosts": ["github.com"],
        "allow-repos": ["dario/corb", "dario/*-docs"],
        "allow-push": false,
      },
      dir: [
        {
          name: "corb",
          host: "~/Code/corb",
          mode: "rw",
          rules: [
            { glob: "**/*_test.go", mode: "deny-write", reason: "tests are frozen for this session" },
            { glob: "**/.env*", mode: "hidden", reason: "local secrets file" },
            { glob: "secrets/**", mode: "hidden", reason: "secrets directory" },
            { glob: ".git/hooks/**", mode: "shadow-write", reason: "keep hooks inert" },
            { glob: ".git/config", mode: "deny-write", reason: "no local git identity changes" },
          ],
        },
        { name: "reference", host: "~/Code/reference-docs", mode: "ro" },
        { name: "scratch", host: "~/.cache/corb/scratch/corb-dev", mode: "rw", create: true },
      ],
      policy: { enabled: true, "secret-scan": true, "max-changed-files": 40, "fail-open": true },
      audit: { path: "~/.local/state/corb/audit.jsonl" },
    });
  });

  it("parses a document with only [[dir]] entries, leaving every other field absent (true partiality)", () => {
    const toml = `
[[dir]]
name = "corb"
host = "~/Code/corb"
mode = "rw"
`;
    const layer = parseConfigLayer(toml, "workspace.toml");

    expect(layer).toEqual({
      dir: [{ name: "corb", host: "~/Code/corb", mode: "rw" }],
    });
    expect(layer.version).toBeUndefined();
    expect(layer.vm).toBeUndefined();
    expect(layer.agent).toBeUndefined();
    expect(layer.secrets).toBeUndefined();
    expect(layer.egress).toBeUndefined();
    expect(layer.git).toBeUndefined();
    expect(layer.policy).toBeUndefined();
    expect(layer.audit).toBeUndefined();
  });

  it("parses an empty document to an empty layer", () => {
    expect(parseConfigLayer("", "empty.toml")).toEqual({});
  });

  it("leaves optional sub-fields absent when not set, without defaulting them", () => {
    const toml = `
[vm]
image = "corb:0.1.0"

[[dir]]
name = "corb"
host = "~/Code/corb"
`;
    const layer = parseConfigLayer(toml, "workspace.toml");

    expect(layer.vm).toEqual({ image: "corb:0.1.0" });
    expect(layer.vm?.memory).toBeUndefined();
    expect(layer.vm?.limits).toBeUndefined();
    expect(layer.dir?.[0]).toEqual({ name: "corb", host: "~/Code/corb" });
    expect(layer.dir?.[0]?.mode).toBeUndefined();
    expect(layer.dir?.[0]?.rules).toBeUndefined();
  });

  it("[vm.limits] present but empty still yields an (empty) object, not undefined", () => {
    const toml = `
[vm]
limits = {}
`;
    const layer = parseConfigLayer(toml, "workspace.toml");
    expect(layer.vm).toEqual({ limits: {} });
  });

  describe("[egress.github-api].hosts", () => {
    it("parses a hosts list alongside methods/deny-paths", () => {
      const toml = `
[egress.github-api]
hosts      = ["ghe.example.com"]
methods    = ["GET"]
deny-paths = ["/user/keys**"]
`;
      const layer = parseConfigLayer(toml, "config.toml");
      expect(layer.egress?.["github-api"]).toEqual({
        hosts: ["ghe.example.com"],
        methods: ["GET"],
        "deny-paths": ["/user/keys**"],
      });
    });

    it("leaves hosts absent when not set, without defaulting it (defaulting is src/policy/github.ts's job, not the parser's)", () => {
      const toml = `
[egress.github-api]
methods = ["GET"]
`;
      const layer = parseConfigLayer(toml, "config.toml");
      expect(layer.egress?.["github-api"]).toEqual({ methods: ["GET"] });
      expect(layer.egress?.["github-api"]?.hosts).toBeUndefined();
    });

    it("hosts alone (no methods/deny-paths) is valid", () => {
      const toml = `
[egress.github-api]
hosts = ["ghe.example.com"]
`;
      const layer = parseConfigLayer(toml, "config.toml");
      expect(layer.egress?.["github-api"]).toEqual({ hosts: ["ghe.example.com"] });
    });

    it("rejects a non-array hosts value the same way methods/deny-paths already reject one", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[egress.github-api]\nhosts = "api.github.com"`, "config.toml"),
      );
      expect(err.message).toContain("field 'egress.github-api.hosts' must be an array");
    });

    it("rejects a typo'd key alongside a valid hosts entry — unknown-key rejection still catches typos", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[egress.github-api]\nhosts = ["api.github.com"]\nhotss = ["oops"]`, "config.toml"),
      );
      expect(err.message).toContain("unknown key 'egress.github-api.hotss'");
    });
  });

  describe("rejects unknown keys", () => {
    it("at the top level", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`bogus = true`, "config.toml"));
      expect(err.message).toContain("config.toml");
      expect(err.message).toContain("unknown key 'bogus'");
      expect(err.location).toBe("bogus");
    });

    it("nested under [vm] (a typo like 'memroy')", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm]\nmemroy = "4G"`, "config.toml"));
      expect(err.message).toContain("unknown key 'vm.memroy'");
      expect(err.location).toBe("vm.memroy");
    });

    it("nested under [vm.limits]", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[vm]\nlimits = { memroy-max = "6G" }`, "config.toml"),
      );
      expect(err.message).toContain("unknown key 'vm.limits.memroy-max'");
    });

    it("inside a [[dir]] table (a typo like 'mdoe')", () => {
      const toml = `
[[dir]]
name = "corb"
host = "~/Code/corb"
mdoe = "rw"
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "workspace.toml"));
      expect(err.message).toContain("unknown key 'dir[0].mdoe'");
      expect(err.location).toBe("dir[0].mdoe");
    });

    it("inside a [[dir]].rules[] entry", () => {
      const toml = `
[[dir]]
name = "corb"
host = "~/Code/corb"
rules = [ { glob = "**/*.env", mode = "hidden", raeson = "typo" } ]
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "workspace.toml"));
      expect(err.message).toContain("unknown key 'dir[0].rules[0].raeson'");
    });

    it("does not misfire on [secrets.NAME]'s arbitrary secret-name keys", () => {
      const toml = `
[secrets.SOME_ARBITRARY_NAME]
hosts = ["example.com"]
[secrets.ANOTHER_ONE]
hosts = ["example.org"]
optional = true
`;
      const layer = parseConfigLayer(toml, "config.toml");
      expect(layer.secrets).toEqual({
        SOME_ARBITRARY_NAME: { hosts: ["example.com"] },
        ANOTHER_ONE: { hosts: ["example.org"], optional: true },
      });
    });

    it("still rejects an unknown key inside one [secrets.NAME] entry's own table", () => {
      const toml = `
[secrets.GITHUB_TOKEN]
hosts = ["api.github.com"]
requried = true
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "config.toml"));
      expect(err.message).toContain("unknown key 'secrets.GITHUB_TOKEN.requried'");
    });

    it("nested under [egress.github-api]", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[egress.github-api]\nmethdos = ["GET"]`, "config.toml"),
      );
      expect(err.message).toContain("unknown key 'egress.github-api.methdos'");
    });
  });

  describe("rejects invalid enum values", () => {
    it("for a dir's own mode", () => {
      const toml = `
[[dir]]
name = "corb"
host = "~/Code/corb"
mode = "read-only"
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "workspace.toml"));
      expect(err.message).toContain("field 'dir[0].mode' has invalid value 'read-only'");
      expect(err.message).toContain("ro");
      expect(err.message).toContain("rw");
    });

    it("for a rule's mode", () => {
      const toml = `
[[dir]]
name = "corb"
host = "~/Code/corb"
rules = [ { glob = "**/*.env", mode = "deny-everything" } ]
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "workspace.toml"));
      expect(err.message).toContain("field 'dir[0].rules[0].mode' has invalid value 'deny-everything'");
      expect(err.message).toContain("shadow-write");
    });

    it("accepts 'shadow-write' as a valid rule mode (the four-mode set, not design.md's stale three)", () => {
      const toml = `
[[dir]]
name = "corb"
host = "~/Code/corb"
rules = [ { glob = ".git/hooks/**", mode = "shadow-write" } ]
`;
      const layer = parseConfigLayer(toml, "workspace.toml");
      expect(layer.dir?.[0]?.rules?.[0]?.mode).toBe("shadow-write");
    });
  });

  describe("rejects malformed opaque-string fields", () => {
    it("vm.memory with a bad size format", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm]\nmemory = "lots"`, "config.toml"));
      expect(err.message).toContain("field 'vm.memory' has invalid format 'lots'");
    });

    it("vm.max-session with a bad duration format", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm]\nmax-session = "four hours"`, "config.toml"));
      expect(err.message).toContain("field 'vm.max-session' has invalid format 'four hours'");
    });

    it("vm.limits.cpu-quota with a bad percentage format", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[vm]\nlimits = { cpu-quota = "400" }`, "config.toml"),
      );
      expect(err.message).toContain("field 'vm.limits.cpu-quota' has invalid format '400'");
    });

    it("vm.limits.memory-max with a bad size format", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[vm]\nlimits = { memory-max = "big" }`, "config.toml"),
      );
      expect(err.message).toContain("field 'vm.limits.memory-max' has invalid format 'big'");
    });

    it("accepts a bare digit size (no suffix) and a single-unit duration", () => {
      const toml = `
[vm]
memory = "1024"
max-session = "4h"
`;
      const layer = parseConfigLayer(toml, "config.toml");
      expect(layer.vm).toEqual({ memory: "1024", "max-session": "4h" });
    });
  });

  describe("type errors", () => {
    it("vm.cpus must be a number", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm]\ncpus = "four"`, "config.toml"));
      expect(err.message).toContain("field 'vm.cpus' must be a number, got string");
    });

    it("vm.limits.pids-max must be a positive integer", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[vm]\nlimits = { pids-max = 0 }`, "config.toml"),
      );
      expect(err.message).toContain("field 'vm.limits.pids-max' must be an integer >= 1, got 0");
    });

    it("[[dir]] must be an array of tables, not a bare table", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[dir]\nname = "corb"`, "config.toml"));
      expect(err.message).toContain("field 'dir' must be an array");
    });

    it("agent.extensions must be an array of strings", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[agent]\nextensions = [1, 2]`, "config.toml"),
      );
      expect(err.message).toContain("field 'agent.extensions[0]' must be a string, got number");
    });
  });

  describe("invalid TOML syntax", () => {
    it("wraps a smol-toml parse failure in a ConfigParseError naming the source", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm\nmemory = "4G"`, "config.toml"));
      expect(err.message).toContain("config.toml");
      expect(err.message).toContain("invalid TOML syntax");
    });
  });
});
