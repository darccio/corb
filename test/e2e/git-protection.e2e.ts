import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RealFSProvider, VM } from "@earendil-works/gondolin";
import { builtinGitRules } from "../../src/config/gitprotect.ts";
import { mergeConfigLayers } from "../../src/config/load.ts";
import { createAuditWriter, type AuditWriter } from "../../src/policy/audit.ts";
import { POLICY_HOST } from "../../src/policy/sentinel.ts";
import { withGlobPolicy } from "../../src/vfs/glob-policy.ts";
import { buildEgressConfig } from "../../src/vm/egress.ts";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import {
  buildGateConfigMount,
  GATE_CONFIG_GUEST_PATH,
  GATE_CONFIG_RAW_ROOT,
  publicWorkspacePath,
  rawWorkspacePath,
  toGlobRules,
} from "../../src/vm/session.ts";

const DIR_NAME = "repo";
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

describe.skipIf(!process.env.CORB_E2E)("git-protection e2e (real VM boot)", () => {
  let tempDir: string;
  let hostRepo: string;
  let originalConfig: Buffer;
  let audit: AuditWriter;
  let vm: VM | undefined;

  beforeAll(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-git-protection-"));
    hostRepo = path.join(tempDir, "repo");
    fs.mkdirSync(hostRepo);
    const git = (...args: string[]) => execFileSync("git", args, { cwd: hostRepo, stdio: "pipe" });
    git("init", "-q");
    git("config", "user.name", "Corb E2E");
    git("config", "user.email", "corb-e2e@example.invalid");
    git("config", "commit.gpgsign", "false");
    fs.writeFileSync(path.join(hostRepo, "initial.txt"), "initial\n");
    git("add", "initial.txt");
    git("commit", "-qm", "initial");
    fs.writeFileSync(path.join(hostRepo, ".git/hooks/pre-commit.sample"), "#!/bin/sh\nexit 0\n");
    fs.mkdirSync(path.join(hostRepo, "prepared-hook"));
    fs.writeFileSync(path.join(hostRepo, "prepared-hook/pre-commit"), "#!/bin/sh\nexit 0\n");
    fs.mkdirSync(path.join(hostRepo, "src"));
    fs.writeFileSync(path.join(hostRepo, "src/main.txt"), "source\n");
    fs.writeFileSync(path.join(hostRepo, "mode.txt"), "mode probe\n", { mode: 0o644 });
    originalConfig = fs.readFileSync(path.join(hostRepo, ".git/config"));

    audit = createAuditWriter({ path: path.join(tempDir, "audit.jsonl") });
    const config = mergeConfigLayers([{ dir: [{ name: DIR_NAME, host: hostRepo }] }]);
    const egress = buildEgressConfig(config.egress, undefined, {}, audit, "git-protection-e2e", config.policy, config.dir);
    vm = await VM.create({
      sandbox: { imagePath: resolveRuntimeImage().assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks: egress.httpHooks,
      env: egress.env,
      vfs: { mounts: {
        [rawWorkspacePath(DIR_NAME)]: withGlobPolicy(new RealFSProvider(hostRepo), {
          rules: toGlobRules(DIR_NAME, builtinGitRules()),
          onDeny: () => {},
        }),
        [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount(),
      } },
      memory: "1G",
      cpus: 2,
      startTimeoutMs: 60_000,
      sessionLabel: "corb-e2e-git-protection",
    });
  }, 180_000);

  afterAll(async () => {
    try {
      await vm?.close();
    } finally {
      audit?.flush();
      if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }, 180_000);

  async function guestShell(script: string) {
    if (!vm) throw new Error("git-protection e2e: VM did not boot");
    return vm.exec(["/usr/local/bin/dropcap", "1000", "1000", "/bin/sh", "-c", `cd ${publicWorkspacePath(DIR_NAME)} && ${script}`], {
      env: {
        PATH: BASE_PATH,
        HOME: "/home/agent",
        CORB_GATE_CONFIG: GATE_CONFIG_GUEST_PATH,
        CORB_POLICY_URL: `http://${POLICY_HOST}/check`,
      },
      stdout: "buffer",
      stderr: "buffer",
      signal: AbortSignal.timeout(30_000),
    });
  }

  it.each([
    ["hook write", "printf 'malicious hook' > .git/hooks/pre-commit"],
    ["directory moved into hooks", "mv prepared-hook .git/hooks/x"],
    ["commondir write", "printf '/tmp/evil' > .git/commondir"],
  ])("denies %s as the agent user", async (_name, command) => {
    const result = await guestShell(command);
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(false);
    expect(fs.readFileSync(path.join(hostRepo, ".git/config"))).toEqual(originalConfig);
    expect(fs.existsSync(path.join(hostRepo, ".git/config.lock"))).toBe(false);
    expect(fs.existsSync(path.join(hostRepo, ".git/commondir"))).toBe(false);
    expect(fs.existsSync(path.join(hostRepo, ".git/hooks/pre-commit"))).toBe(false);
    expect(fs.existsSync(path.join(hostRepo, ".git/hooks/x"))).toBe(false);
  });

  it("keeps remote config private and visible across guest commands", async () => {
    const added = await guestShell("git remote add x https://example.invalid/team/repo.git && git remote -v");
    expect(added.ok, `exit ${added.exitCode}: ${added.stderr}`).toBe(true);
    expect(added.stdout).toContain("x\thttps://example.invalid/team/repo.git (fetch)");
    expect(added.stdout).toContain("x\thttps://example.invalid/team/repo.git (push)");
    const later = await guestShell("git remote -v");
    expect(later.ok, later.stderr).toBe(true);
    expect(later.stdout).toContain("x\thttps://example.invalid/team/repo.git");
    expect(fs.readFileSync(path.join(hostRepo, ".git/config"))).toEqual(originalConfig);
    expect(fs.existsSync(path.join(hostRepo, ".git/config.lock"))).toBe(false);
    expect(execFileSync("git", ["remote", "-v"], { cwd: hostRepo, encoding: "utf8" })).toBe("");
  });

  it("accepts shell and unshimmed config changes only in the guest", async () => {
    const result = await guestShell("printf '[corb]\\n\\tprivate = shell\\n' >> .git/config && /usr/local/libexec/real-git config corb.private updated && /usr/local/libexec/real-git config --get corb.private");
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout).toBe("updated\n");
    expect(fs.readFileSync(path.join(hostRepo, ".git/config"))).toEqual(originalConfig);
    expect(fs.existsSync(path.join(hostRepo, ".git/config.lock"))).toBe(false);
  });

  it("still allows status, add and commit through the git shim", async () => {
    const result = await guestShell("git status --porcelain && printf 'new file\\n' > added.txt && git add added.txt && git commit -m 'guest commit'");
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(execFileSync("git", ["log", "-1", "--format=%s"], { cwd: hostRepo, encoding: "utf8" }).trim()).toBe("guest commit");
    expect(fs.readFileSync(path.join(hostRepo, ".git/config"))).toEqual(originalConfig);
    expect(fs.existsSync(path.join(hostRepo, ".git/index.lock"))).toBe(false);
  });

  it("still allows ordinary directory renames", async () => {
    const result = await guestShell("mv src lib && cat lib/main.txt");
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout).toBe("source\n");
    expect(fs.existsSync(path.join(hostRepo, "src"))).toBe(false);
    expect(fs.readFileSync(path.join(hostRepo, "lib/main.txt"), "utf8")).toBe("source\n");
  });

  it("records what guest chmod does to a workspace file", async () => {
    const hostMode = fs.statSync(path.join(hostRepo, "mode.txt")).mode & 0o777;
    const result = await guestShell("chmod 0777 mode.txt; result=$?; printf 'chmod_exit=%s\\n' \"$result\"; stat -c 'guest_mode=%a' mode.txt");
    expect(result.ok, result.stderr).toBe(true);
    expect(result.stdout).toContain("chmod_exit=");
    expect(fs.statSync(path.join(hostRepo, "mode.txt")).mode & 0o777).toBe(hostMode);
    console.info(`workspace chmod probe: ${result.stdout.trim()}; host_mode=${hostMode.toString(8)}`);
  });
});
