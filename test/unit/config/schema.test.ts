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

    it("parses a full [secrets.NAME.verify] table", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
url = "https://api.anthropic.com/v1/models"
header = "x-api-key"
expect-status = [200, 400]
`;
      const layer = parseConfigLayer(toml, "config.toml");
      expect(layer.secrets).toEqual({
        ANTHROPIC_API_KEY: {
          hosts: ["api.anthropic.com"],
          verify: {
            url: "https://api.anthropic.com/v1/models",
            header: "x-api-key",
            "expect-status": [200, 400],
          },
        },
      });
    });

    it("[secrets.NAME.verify] omitting expect-status leaves it undefined (default applied by the consumer, not the parser)", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
url = "https://api.anthropic.com/v1/models"
header = "x-api-key"
`;
      const layer = parseConfigLayer(toml, "config.toml");
      expect(layer.secrets?.ANTHROPIC_API_KEY?.verify).toEqual({
        url: "https://api.anthropic.com/v1/models",
        header: "x-api-key",
      });
    });

    it("rejects a [secrets.NAME.verify] table missing 'url'", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
header = "x-api-key"
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "config.toml"));
      expect(err.message).toContain("secrets.ANTHROPIC_API_KEY.verify");
      expect(err.message).toContain("url");
    });

    it("rejects a [secrets.NAME.verify] table missing 'header'", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
url = "https://api.anthropic.com/v1/models"
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "config.toml"));
      expect(err.message).toContain("secrets.ANTHROPIC_API_KEY.verify");
      expect(err.message).toContain("header");
    });

    it("rejects a non-https [secrets.NAME.verify] url", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
url = "http://api.anthropic.com/v1/models"
header = "x-api-key"
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "config.toml"));
      expect(err.message).toContain("invalid format");
    });

    it("rejects an empty expect-status list", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
url = "https://api.anthropic.com/v1/models"
header = "x-api-key"
expect-status = []
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "config.toml"));
      expect(err.message).toContain("must not be empty");
    });

    it("rejects an out-of-range expect-status entry", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
url = "https://api.anthropic.com/v1/models"
header = "x-api-key"
expect-status = [999]
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "config.toml"));
      expect(err.message).toContain("must be a valid HTTP status code");
    });

    it("rejects an unknown key inside [secrets.NAME.verify]", () => {
      const toml = `
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
[secrets.ANTHROPIC_API_KEY.verify]
url = "https://api.anthropic.com/v1/models"
header = "x-api-key"
methdo = "GET"
`;
      const err = expectConfigParseError(() => parseConfigLayer(toml, "config.toml"));
      expect(err.message).toContain("unknown key 'secrets.ANTHROPIC_API_KEY.verify.methdo'");
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

    // vm.memory and vm.limits.memory-max used to share one case-insensitive,
    // optional-suffix regex even though their consumers have incompatible
    // unit semantics: a bare number is megabytes for QEMU's `-m` (vm.memory)
    // but bytes for systemd's `MemoryMax=` (vm.limits.memory-max), and only
    // systemd's grammar is documented as uppercase-only. The tests below
    // pin the two fields' now-separate, consumer-accurate formats.
    describe("vm.memory / vm.limits.memory-max no longer share one format", () => {
      it("vm.memory still accepts a bare number (QEMU's own bare-megabytes convention)", () => {
        const layer = parseConfigLayer(`[vm]\nmemory = "4096"`, "config.toml");
        expect(layer.vm?.memory).toBe("4096");
      });

      it("vm.memory still accepts an uppercase M or G suffix", () => {
        const layer = parseConfigLayer(`[vm]\nmemory = "4G"`, "config.toml");
        expect(layer.vm?.memory).toBe("4G");
      });

      it("vm.memory now rejects a K or T suffix (QEMU's -m man page only documents M/G)", () => {
        const errK = expectConfigParseError(() => parseConfigLayer(`[vm]\nmemory = "4096K"`, "config.toml"));
        expect(errK.message).toContain("field 'vm.memory' has invalid format '4096K'");
        const errT = expectConfigParseError(() => parseConfigLayer(`[vm]\nmemory = "1T"`, "config.toml"));
        expect(errT.message).toContain("field 'vm.memory' has invalid format '1T'");
      });

      it("vm.limits.memory-max now rejects a bare number -- regression test for the memory/memory-max unit-confusion footgun", () => {
        const err = expectConfigParseError(() =>
          parseConfigLayer(`[vm]\nlimits = { memory-max = "6144" }`, "config.toml"),
        );
        expect(err.message).toContain("field 'vm.limits.memory-max' has invalid format '6144'");
      });

      it("vm.limits.memory-max still rejects a lowercase suffix (systemd's grammar is uppercase-only)", () => {
        const err = expectConfigParseError(() =>
          parseConfigLayer(`[vm]\nlimits = { memory-max = "6g" }`, "config.toml"),
        );
        expect(err.message).toContain("field 'vm.limits.memory-max' has invalid format '6g'");
      });

      it("vm.limits.memory-max accepts a valid uppercase-suffixed value for each of K, M, G, T", () => {
        for (const value of ["6144K", "6M", "6G", "2T"]) {
          const layer = parseConfigLayer(`[vm]\nlimits = { memory-max = "${value}" }`, "config.toml");
          expect(layer.vm?.limits?.["memory-max"]).toBe(value);
        }
      });
    });
  });

  // D1: `vm.max-session` fed straight into `setTimeout` (via `src/vm/
  // watchdog.ts`) with no upper bound. Node's `setTimeout` delay is a signed
  // 32-bit integer, so a value past `2**31 - 1` ms (~24.855 days) doesn't
  // error there -- it silently clamps to a ~1ms timer and fires almost
  // immediately instead of after the configured delay. These tests are the
  // *primary* defense for that finding: `corb.toml` must fail to parse
  // outright for an out-of-range `max-session`, so `corb run` errors clearly
  // and immediately instead of silently mis-timing a session three layers
  // downstream. (The corresponding unit-level bound check lives in
  // `test/unit/util/duration.test.ts`, on `parseDuration` itself.)
  describe("vm.max-session overflow guard (D1)", () => {
    it("accepts the README's own example value ('4h')", () => {
      const layer = parseConfigLayer(`[vm]\nmax-session = "4h"`, "config.toml");
      expect(layer.vm?.["max-session"]).toBe("4h");
    });

    it("accepts another safely-small value ('24d', just under the ~24.855-day bound)", () => {
      const layer = parseConfigLayer(`[vm]\nmax-session = "24d"`, "config.toml");
      expect(layer.vm?.["max-session"]).toBe("24d");
    });

    it("rejects '25d' with a ConfigParseError naming the field -- regression test for the finding", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm]\nmax-session = "25d"`, "config.toml"));
      expect(err.message).toContain("vm.max-session");
      expect(err.location).toBe("vm.max-session");
    });

    it("rejects '600h' the same way -- the bound applies regardless of which unit produced the overflow", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm]\nmax-session = "600h"`, "config.toml"));
      expect(err.message).toContain("vm.max-session");
    });

    it("overflow error states the actual reason (setTimeout) and the precise bound, distinct from a plain invalid-format error", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[vm]\nmax-session = "25d"`, "config.toml"));
      expect(err.message).toContain("setTimeout");
      expect(err.message).toContain("2147483647");
      expect(err.message).not.toContain("invalid format");
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

  // E2: `version` used to accept any number with zero semantic validation —
  // parsed, merged, and shown by `corb explain` as if it meant something,
  // but never actually compared against anything corb itself understands.
  // It now has a real (if trivial) semantics: it must equal the one schema
  // generation this build understands.
  describe("version (E2: validated against the schema generation corb understands)", () => {
    it("version = 1 parses fine (already covered by the full-document test above; confirmed again here in isolation)", () => {
      const layer = parseConfigLayer(`version = 1`, "config.toml");
      expect(layer.version).toBe(1);
    });

    it("an omitted version parses fine (already covered by the partiality test above)", () => {
      const layer = parseConfigLayer(`name = "corb-dev"`, "config.toml");
      expect(layer.version).toBeUndefined();
    });

    it("version = 2 throws ConfigParseError naming both the declared and expected version", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`version = 2`, "config.toml"));
      expect(err.message).toContain("field 'version'");
      expect(err.message).toContain("declares 2");
      expect(err.message).toContain("only understands version 1");
      expect(err.location).toBe("version");
    });
  });

  // E2: `agent.extensions`/`agent.append-system-prompt-file` used to be
  // parsed, merged across layers, and shown by `corb explain` with zero
  // downstream effect — a fully-corroborating UI for a no-op, since nothing
  // forwards either to `pi` (README.md). Rather than wire up a real feature
  // (out of scope for this fix), both are now rejected outright at parse
  // time so the no-op can no longer be silently configured.
  describe("agent.extensions / agent.append-system-prompt-file (E2: rejected, not silently accepted)", () => {
    it("agent.append-system-prompt-file throws ConfigParseError for any value", () => {
      const err = expectConfigParseError(() =>
        parseConfigLayer(`[agent]\nappend-system-prompt-file = "~/.config/corb/APPEND_SYSTEM.md"`, "config.toml"),
      );
      expect(err.message).toContain("field 'agent.append-system-prompt-file'");
      expect(err.location).toBe("agent.append-system-prompt-file");
    });

    it("agent.extensions = [\"foo\"] (non-empty) throws ConfigParseError", () => {
      const err = expectConfigParseError(() => parseConfigLayer(`[agent]\nextensions = ["foo"]`, "config.toml"));
      expect(err.message).toContain("field 'agent.extensions'");
      expect(err.location).toBe("agent.extensions");
    });

    it("agent.extensions = [] (empty) still parses fine -- not a lie, since corb loading zero extensions is accurate", () => {
      const layer = parseConfigLayer(`[agent]\nextensions = []`, "config.toml");
      expect(layer.agent?.extensions).toEqual([]);
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
