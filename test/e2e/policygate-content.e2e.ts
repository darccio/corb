// M7.4 — real-VM proof that M7's own stated accept criteria
// (`docs/design.md` §10) for the local git/gh gate (§4) and the
// out-of-guest content-check sentinel (§5) actually hold against a booted
// guest running the real, shipped `policygate` binary and the real
// `sentinel()`/`checks.ts` host-side stack — not just against
// `guest/internal/gate/*_test.go`'s in-process Go unit tests or
// `test/unit/policy/{sentinel,checks}.test.ts`'s synthetic `Request`
// objects. Matches M7's own three literal accept-criteria plus the exit-86
// local-denial case (cheap, and it exercises the other documented exit
// code):
//
//   - "A commit containing a secret-shaped string is blocked with a
//     structured error and exit 87; a local table denial exits 86."
//   - "An unreachable check service does not block commits, and the audit
//     log records that the check did not run."
//   - "The audit log contains at least one entry from each of the [...]
//     channels after a representative session."
//
// Gating and layout matches every other suite in this directory exactly:
// `vitest.config.ts` never matches `test/e2e/**`, so a plain `npm test`
// never touches this file, and `describe.skipIf` below additionally gates
// the whole suite on `CORB_E2E=1`. Run via `CORB_E2E=1 npx vitest run
// --config vitest.e2e.config.ts test/e2e/policygate-content.e2e.ts`,
// `npm run test:e2e`, or `make e2e`.
//
// ## Why two VM boots, one per `describe` block
//
// `policy.enabled` is baked into `VM.create()`'s `httpHooks` closure at boot
// time, via `sentinel()`'s own closure over `policy` (`src/policy/
// sentinel.ts`) — it cannot be toggled mid-session. So this suite boots two
// separate VMs, each with its own `beforeAll`/`afterAll`:
//
//   - **Scenario A** ("content-check enabled"): `policy.enabled = true`.
//     Exercises the real secret-scan denial (exit 87), the real local-table
//     denial (exit 86), and a real `vfs`-channel deny.
//   - **Scenario B** ("content-check disabled / fail-open"): `policy.enabled
//     = false`. With the sentinel disabled, the guest's `policygate` POST to
//     `CORB_POLICY_URL` (`http://policy.corb.invalid/check`) genuinely fails
//     to connect — `policy.corb.invalid` is an RFC 2606 `.invalid` name that
//     can never resolve, and per `docs/gondolin-notes.md` §4 ("the host
//     enforces against the HTTP `Host` header and performs its own
//     resolution"), that resolution happens for real, on the host, and fails
//     fast (not a slow timeout). `policygate`'s own fail-open path
//     (`guest/internal/gate/main.go`'s `runContentCheck`) then lets the
//     commit through. This is the literal mechanism `docs/design.md` §5's
//     "An unreachable or erroring check service fails open" describes — this
//     suite triggers the real fail-open path by disabling the sentinel hook
//     entirely, rather than simulating it.
//
// ## Why git repo setup happens entirely host-side
//
// `src/vm/session.ts`'s exported `GATE_CONFIG` (see below) has `git`'s
// `blockedSubcommands: ["config", "credential", "filter-branch", "init"]` —
// both `init` and `config` are locally blocked by `policygate` itself (exit
// 86). So `git init`/`git config user.email`/`git config user.name` run on
// the **host**, via `execFileSync`, against a real `fs.mkdtempSync`
// directory, before that directory is ever mounted into the guest — mirrors
// `test/e2e/git-ssh-policy.e2e.ts`'s own `setupBareRepo()` host-side
// pattern. Only `git add`/`git commit` — the subcommands actually under
// test — ever go through the guest's shimmed `/usr/local/bin/git`.
//
// ## Reuses `src/vm/session.ts`'s exact `gate.json` mount, not a duplicate
//
// `buildGateConfigMount()` (newly exported by `src/vm/session.ts` for this
// item) constructs the identical, populated, read-only `MemoryProvider`/
// `ReadonlyProvider` mount `runSession()` itself now calls — see that
// function's own doc comment. Mirrors `workspace-mounts.e2e.ts`'s own stated
// reasoning for importing `rawWorkspacePath`/`publicWorkspacePath` rather
// than re-deriving them: a drift between this test's `gate.json` and
// production's `gate.json` would fail this suite, not silently diverge.
//
// ## Audit-channel scope: `gate`, `vfs`, `session` only
//
// M7's own accept line requires "audit.jsonl has an entry from each
// channel" (http, ssh, vfs, gate, session), but `http` and `ssh` are already
// independently, thoroughly proven by `test/e2e/egress.e2e.ts` and
// `test/e2e/git-ssh-policy.e2e.ts` — out of scope here. This suite exercises
// and asserts on the three channels actually new or touched by M7:
//
//   - `gate`: comes for free from Scenario A's AKIA-commit denial
//     (`sentinel.ts` records it against `POLICY_HOST`).
//   - `vfs`: Scenario A's workspace mount carries one real `deny-write` rule
//     (`PROTECTED_FILE_NAME`), exercised via a denied guest-side write
//     through `guestShellA()`. Scenario A carries this assertion (not B)
//     because it's already booting a VM with a workspace mount for the git
//     scenarios, so no extra VM boot is needed.
//   - `session`: `src/vm/session.ts`'s own `runSession()` records
//     `channel: "session"` events (`reason: "start"` before `VM.create()`,
//     `` `exit:${code}` `` after the interactive exec, `"error"` in its
//     `catch`) — but those are woven into the interactive-TUI flow every e2e
//     suite in this codebase deliberately avoids calling (see "Why this
//     drives `VM.create()` directly" in `workspace-mounts.e2e.ts`'s own
//     module comment for the shared reasoning). Since this suite drives
//     `VM.create()`/`vm.exec()` directly instead, it records its own
//     `channel: "session"` audit events around its own VM lifecycle (before
//     `VM.create()`, after teardown), matching `session.ts`'s exact event
//     shape. This *mirrors* `session.ts`'s own recording rather than calling
//     it — documented here, the same way this file's host-side git setup
//     mirrors `git-ssh-policy.e2e.ts`'s own pattern rather than importing
//     anything from it.
//
// ## `gate.json` mount: regression test for a previously-shipped bug
//
// This suite mounts `buildGateConfigMount()`'s provider at
// `GATE_CONFIG_RAW_ROOT` — the exact same internal-only, root-only guest path
// `runSession()` itself mounts it at — not at the public `GATE_CONFIG_MOUNT_ROOT`
// (`/run/corb`). That distinction is the point of this suite: M7.3 originally
// mounted the provider directly at the public path, which is a raw
// `vfs.mounts` entry that Gondolin's `sandboxfs` mounts `user_id=0` with no
// `allow_other` (exactly like `WORKSPACE_RAW_ROOT` before the M1.6 `bindfs`
// fix, `docs/gondolin-notes.md` R5/R12/R18) — so the dropped-privilege `agent`
// uid (1000) got `EACCES` reading `gate.json` at the guest kernel FUSE layer,
// before any file-level permission was ever consulted. Confirmed
// independently against a real booted `corb:0.1.0` image (2026-08-28):
// `dropcap 1000 1000 cat /run/corb/gate.json` → `Permission denied`;
// `policygate` itself → exit 78, "local policy table unavailable... permission
// denied". `policygate` could not read its own config in *any* real session.
// The fix mounts the provider at the internal-only `GATE_CONFIG_RAW_ROOT`
// instead and generalizes `image/overlay/init-extra.sh`'s existing
// `WORKSPACE_RAW_ROOT` → `bindfs --force-user`/`--force-group` →
// `WORKSPACE_PUBLIC_ROOT` re-export loop to also re-export this one
// always-present mount to the public `/run/corb`. This suite drives that same
// raw mount point so it exercises the real boot-time re-export, not a
// bypass of it.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RealFSProvider, VM, type ExecResult, type VirtualProvider } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { buildEgressConfig } from "../../src/vm/egress.ts";
import {
  buildGateConfigMount,
  GATE_CONFIG_RAW_ROOT,
  GATE_CONFIG_GUEST_PATH,
  publicWorkspacePath,
  rawWorkspacePath,
  toGlobRules,
} from "../../src/vm/session.ts";
import { withGlobPolicy, type GlobPolicyDenyEvent } from "../../src/vfs/glob-policy.ts";
import { createAuditWriter, type AuditEvent, type AuditWriter } from "../../src/policy/audit.ts";
import { POLICY_HOST } from "../../src/policy/sentinel.ts";
import type { DirRuleConfig, EffectiveEgressConfig, EffectivePolicyConfig } from "../../src/config/load.ts";

// Matches `image/corb-image.json`'s `postBuild.commands` and
// `image/verify.ts`'s own hardcoded convention, exactly like every other e2e
// suite — not read dynamically from `/etc/corb/image.json` here, see those
// suites' own module comments for why.
const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";
const GUEST_HOME = "/home/agent";

// No login shell for any exec (array-form `exec` runs none), matching
// `image/verify.ts`'s own `BASE_PATH` convention.
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

// The one workspace directory each scenario mounts its own host-side git
// repo at. Reused by name across both scenarios' separate VMs — no
// collision, since each scenario boots its own VM with its own mounts.
const DIR_NAME = "repo";

const PROTECTED_FILE_NAME = "protected.txt";
const PROTECTED_FILE_CONTENT = "do not touch (vfs-channel proof fixture)\n";

// The M7 acceptance test's own exact secret shape (`docs/design.md` §10,
// `src/policy/checks.ts`'s `SECRET_PATTERNS`, already unit-tested in
// `test/unit/policy/checks.test.ts`): `AKIA` + exactly 16 uppercase-alnum
// characters.
const AKIA_STRING = "AKIAABCDEFGHIJKLMNOP";
const SECRET_FILE_NAME = "secret.txt";

const SESSION_ID_A = "corb-e2e-policygate-content-a";
const SESSION_LABEL_A = "corb-e2e-policygate-content-a";
const SESSION_ID_B = "corb-e2e-policygate-content-b";
const SESSION_LABEL_B = "corb-e2e-policygate-content-b";

const EGRESS: EffectiveEgressConfig = {
  "block-internal-ranges": true,
  websockets: false,
  allow: [],
};

const POLICY_ENABLED: EffectivePolicyConfig = { enabled: true, "secret-scan": true, "fail-open": true };
const POLICY_DISABLED: EffectivePolicyConfig = { enabled: false, "secret-scan": true, "fail-open": true };

/**
 * Creates a bare host-side git repo directory and configures `user.email`/
 * `user.name` — all via a real, unshimmed `git`, entirely before the
 * directory is ever mounted into a guest. See the module comment's "Why git
 * repo setup happens entirely host-side" section: `git init`/`git config`
 * are both locally blocked by `policygate` (exit 86), so exercising them
 * would have to happen here, not through the guest's shimmed git.
 */
function setupHostRepo(repoPath: string): void {
  fs.mkdirSync(repoPath, { recursive: true });
  execFileSync("git", ["init", "-q", repoPath], { stdio: "pipe" });
  execFileSync("git", ["-C", repoPath, "config", "user.email", "corb-e2e@example.invalid"], { stdio: "pipe" });
  execFileSync("git", ["-C", repoPath, "config", "user.name", "Corb E2E"], { stdio: "pipe" });
}

/** Guest env every `guestShell` exec needs — matches `src/vm/session.ts`'s own `buildGuestEnv()` for the two `policygate`-specific vars. */
function guestEnv(): Record<string, string> {
  return {
    PATH: BASE_PATH,
    HOME: GUEST_HOME,
    CORB_POLICY_URL: `http://${POLICY_HOST}/check`,
    CORB_GATE_CONFIG: GATE_CONFIG_GUEST_PATH,
  };
}

/** Runs a shell script as the dropped-privilege `agent` uid via `dropcap`, cwd at the mounted repo's public path — mirrors every other e2e suite's `guestShell` helper. */
async function guestShellIn(vm: VM, script: string): Promise<ExecResult> {
  return vm.exec(
    [DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh", "-c", `cd ${publicWorkspacePath(DIR_NAME)} && ${script}`],
    { env: guestEnv(), stdout: "buffer", stderr: "buffer" },
  );
}

describe.skipIf(!process.env.CORB_E2E)("policygate-content e2e (real VM boot)", () => {
  describe("Scenario A: content-check enabled (policy.enabled=true)", () => {
    let hostRepoDir: string;
    let auditPath: string;
    let audit: AuditWriter;
    let vm: VM | undefined;

    beforeAll(async () => {
      hostRepoDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-policygate-content-a-"));
      setupHostRepo(hostRepoDir);
      fs.writeFileSync(path.join(hostRepoDir, PROTECTED_FILE_NAME), PROTECTED_FILE_CONTENT);

      const tmpAuditDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-policygate-content-a-audit-"));
      auditPath = path.join(tmpAuditDir, "audit.jsonl");
      audit = createAuditWriter({ path: auditPath });

      // `vfs`-channel coverage: one real `deny-write` rule on this
      // scenario's own workspace mount — see the module comment's
      // "Audit-channel scope" section for why Scenario A (not B) carries
      // this assertion.
      const rawRules: DirRuleConfig[] = [
        { glob: PROTECTED_FILE_NAME, mode: "deny-write", reason: "vfs-channel proof fixture, read-only for this session" },
      ];
      const onVfsDeny = (event: GlobPolicyDenyEvent): void => {
        const subject = event.path === "" ? event.op : `${event.op} ${event.path}`;
        const reason =
          event.outcome.kind === "shadowed"
            ? `shadowed (redirected to ephemeral storage): ${event.reason}`
            : event.reason;
        audit.record({ channel: "vfs", decision: "deny", subject, reason, sessionId: SESSION_ID_A });
      };
      const base: VirtualProvider = new RealFSProvider(hostRepoDir);
      const vfsMounts: Record<string, VirtualProvider> = {
        [rawWorkspacePath(DIR_NAME)]: withGlobPolicy(base, { rules: toGlobRules(DIR_NAME, rawRules), onDeny: onVfsDeny }),
        // Reuses `session.ts`'s exact production `gate.json` mount — see the
        // module comment's "Reuses `src/vm/session.ts`'s exact `gate.json`
        // mount" section.
        [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount(),
      };

      const egressConfig = buildEgressConfig(EGRESS, undefined, {}, audit, SESSION_ID_A, POLICY_ENABLED, []);

      // `session` channel: mirrors, rather than calls, `session.ts`'s own
      // "start" event — see the module comment's "Audit-channel scope"
      // section for why.
      audit.record({ channel: "session", decision: "allow", subject: SESSION_LABEL_A, reason: "start", sessionId: SESSION_ID_A });

      const resolvedImage = resolveRuntimeImage();
      vm = await VM.create({
        sandbox: { imagePath: resolvedImage.assetDir },
        dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
        httpHooks: egressConfig.httpHooks,
        env: egressConfig.env,
        allowWebSockets: egressConfig.allowWebSockets,
        vfs: { mounts: vfsMounts },
        sessionLabel: SESSION_LABEL_A,
      });
    }, 180_000);

    afterAll(async () => {
      try {
        if (vm) {
          await vm.close();
        }
      } finally {
        audit?.record({ channel: "session", decision: "allow", subject: SESSION_LABEL_A, reason: "exit:teardown", sessionId: SESSION_ID_A });
        audit?.flush();
        if (hostRepoDir) {
          fs.rmSync(hostRepoDir, { recursive: true, force: true });
        }
        if (auditPath) {
          fs.rmSync(path.dirname(auditPath), { recursive: true, force: true });
        }
      }
    }, 180_000);

    function requireVm(): VM {
      if (!vm) {
        throw new Error("policygate-content e2e (Scenario A): VM was not booted (beforeAll must have failed)");
      }
      return vm;
    }

    async function guestShellA(script: string): Promise<ExecResult> {
      return guestShellIn(requireVm(), script);
    }

    it("a commit containing an AWS-access-key-shaped string is blocked with exit 87 (secret-in-diff)", async () => {
      const result = await guestShellA(
        `echo "aws_key = ${AKIA_STRING}" > ${SECRET_FILE_NAME} && git add ${SECRET_FILE_NAME} && git commit -m "add secret"`,
      );
      expect(result.exitCode, `stderr: ${result.stderr}`).toBe(87);
      // Matching `guest/internal/gate/format.go`'s `FormatContentDenial`
      // substrings that matter for this scenario — not the full byte-for-byte
      // string, since violation ordering/count phrasing is an implementation
      // detail already locked down by that file's own unit tests.
      expect(result.stderr).toContain("blocked by corb policy");
      expect(result.stderr).toContain("secret-in-diff");
    });

    it("a locally-blocked git subcommand (git config) exits 86", async () => {
      const result = await guestShellA(`git config user.name nope`);
      expect(result.exitCode, `stderr: ${result.stderr}`).toBe(86);
      // Matches `guest/internal/gate/format.go`'s `FormatLocalDenial` exactly.
      expect(result.stderr).toContain("is blocked in this sandbox");
    });

    it("git -C does not bypass the content check: a commit with an AWS-access-key-shaped string via 'git -C .' still exits 87", async () => {
      // Regression for the args[0]-only dispatch bug: `git -C . commit` used
      // to have args[0] == "-C", so neither CheckLocal's subcommand check nor
      // policygate's GatedHook dispatch (also keyed on args[0]) ever saw
      // "commit" at all, and the commit went through with zero content check.
      const result = await guestShellA(
        `echo "aws_key = ${AKIA_STRING}" > ${SECRET_FILE_NAME}-via-dash-c && git add ${SECRET_FILE_NAME}-via-dash-c && git -C . commit -m "add secret via -C"`,
      );
      expect(result.exitCode, `stderr: ${result.stderr}`).toBe(87);
      expect(result.stderr).toContain("blocked by corb policy");
      expect(result.stderr).toContain("secret-in-diff");
    });

    it("git -C does not bypass the locally-blocked config subcommand", async () => {
      const result = await guestShellA(`git -C . config user.name nope`);
      expect(result.exitCode, `stderr: ${result.stderr}`).toBe(86);
      expect(result.stderr).toContain("is blocked in this sandbox");
    });

    it("a write to a deny-write-covered path is denied at the vfs layer, and the host file is unchanged", async () => {
      const result = await guestShellA(`echo overwrite >> ${PROTECTED_FILE_NAME}`);
      expect(result.ok, "a write to a deny-write path unexpectedly succeeded").toBe(false);

      const hostContent = fs.readFileSync(path.join(hostRepoDir, PROTECTED_FILE_NAME), "utf8");
      expect(hostContent, "the host file's content changed despite the write being denied").toBe(PROTECTED_FILE_CONTENT);
    });

    it("audit log: a gate-channel deny, a vfs-channel deny, and a session-channel entry are all on disk after flush()", () => {
      audit.flush();
      expect(fs.existsSync(auditPath)).toBe(true);
      const lines = fs
        .readFileSync(auditPath, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as AuditEvent);

      const gateDeny = lines.find(
        (event) =>
          event.channel === "gate" &&
          event.decision === "deny" &&
          event.subject === "git.commit" &&
          event.reason?.includes("secret-in-diff"),
      );
      expect(gateDeny, `no matching gate/deny entry in: ${JSON.stringify(lines)}`).toBeDefined();
      expect(gateDeny?.sessionId).toBe(SESSION_ID_A);

      const vfsDeny = lines.find(
        (event) => event.channel === "vfs" && event.decision === "deny" && event.subject.includes(PROTECTED_FILE_NAME),
      );
      expect(vfsDeny, `no matching vfs/deny entry in: ${JSON.stringify(lines)}`).toBeDefined();

      const sessionEntry = lines.find((event) => event.channel === "session");
      expect(sessionEntry, `no session-channel entry in: ${JSON.stringify(lines)}`).toBeDefined();
      expect(sessionEntry?.sessionId).toBe(SESSION_ID_A);
    });
  });

  describe("Scenario B: content-check disabled / fail-open (policy.enabled=false)", () => {
    let hostRepoDir: string;
    let auditPath: string;
    let audit: AuditWriter;
    let vm: VM | undefined;

    beforeAll(async () => {
      hostRepoDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-policygate-content-b-"));
      setupHostRepo(hostRepoDir);

      const tmpAuditDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-policygate-content-b-audit-"));
      auditPath = path.join(tmpAuditDir, "audit.jsonl");
      audit = createAuditWriter({ path: auditPath });

      const base: VirtualProvider = new RealFSProvider(hostRepoDir);
      const vfsMounts: Record<string, VirtualProvider> = {
        [rawWorkspacePath(DIR_NAME)]: withGlobPolicy(base, { rules: [], onDeny: () => {} }),
        [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount(),
      };

      const egressConfig = buildEgressConfig(EGRESS, undefined, {}, audit, SESSION_ID_B, POLICY_DISABLED, []);

      audit.record({ channel: "session", decision: "allow", subject: SESSION_LABEL_B, reason: "start", sessionId: SESSION_ID_B });

      const resolvedImage = resolveRuntimeImage();
      vm = await VM.create({
        sandbox: { imagePath: resolvedImage.assetDir },
        dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
        httpHooks: egressConfig.httpHooks,
        env: egressConfig.env,
        allowWebSockets: egressConfig.allowWebSockets,
        vfs: { mounts: vfsMounts },
        sessionLabel: SESSION_LABEL_B,
      });
    }, 180_000);

    afterAll(async () => {
      try {
        if (vm) {
          await vm.close();
        }
      } finally {
        audit?.record({ channel: "session", decision: "allow", subject: SESSION_LABEL_B, reason: "exit:teardown", sessionId: SESSION_ID_B });
        audit?.flush();
        if (hostRepoDir) {
          fs.rmSync(hostRepoDir, { recursive: true, force: true });
        }
        if (auditPath) {
          fs.rmSync(path.dirname(auditPath), { recursive: true, force: true });
        }
      }
    }, 180_000);

    function requireVm(): VM {
      if (!vm) {
        throw new Error("policygate-content e2e (Scenario B): VM was not booted (beforeAll must have failed)");
      }
      return vm;
    }

    async function guestShellB(script: string): Promise<ExecResult> {
      return guestShellIn(requireVm(), script);
    }

    it("fail-open verified: with policy.enabled=false, a commit with the same AKIA-shaped secret succeeds (exit 0) and policygate's own fail-open note is on stderr", async () => {
      const result = await guestShellB(
        `echo "aws_key = ${AKIA_STRING}" > ${SECRET_FILE_NAME} && git add ${SECRET_FILE_NAME} && git commit -m "add secret"`,
      );
      expect(result.exitCode, `stderr: ${result.stderr}`).toBe(0);
      // `guest/internal/gate/main.go`'s `runContentCheck`: printed when the
      // POST to `CORB_POLICY_URL` fails outright (here: a real host-side DNS
      // resolution failure for the RFC 2606 `.invalid` sentinel hostname,
      // since `sentinel()` never intercepts the request at all with
      // `policy.enabled=false`) — distinguishes a genuinely-exercised
      // fail-open path from "the check was silently never attempted for some
      // other reason".
      expect(result.stderr).toContain("policygate: content check unreachable, proceeding");
    });

    it("audit log: at least one session-channel entry is present, and no gate-channel entry was ever recorded", () => {
      audit.flush();
      expect(fs.existsSync(auditPath)).toBe(true);
      const lines = fs
        .readFileSync(auditPath, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as AuditEvent);

      const sessionEntry = lines.find((event) => event.channel === "session");
      expect(sessionEntry, `no session-channel entry in: ${JSON.stringify(lines)}`).toBeDefined();
      expect(sessionEntry?.sessionId).toBe(SESSION_ID_B);

      // Scenario B's request never reaches `sentinel()` at all — it's
      // disabled (`policy.enabled=false`'s step 1 in `sentinel.ts`), so
      // there is no `gate`-channel event to expect here, unlike Scenario A.
      const gateEntry = lines.find((event) => event.channel === "gate");
      expect(gateEntry, `unexpected gate-channel entry in: ${JSON.stringify(lines)}`).toBeUndefined();
    });
  });
});
