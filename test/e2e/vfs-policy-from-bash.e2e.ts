// M5.5 — real-VM proof that M5's glob-based VFS policy stack
// (`src/vfs/glob.ts` M5.1, `src/vfs/policy.ts` M5.2, `src/vfs/glob-policy.ts`'s
// `withGlobPolicy` M5.3, wired into `src/vm/session.ts`'s real mount loop
// M5.4) actually holds against a booted guest and a real `RealFSProvider` /
// real FUSE / VFS-RPC boundary — not just against `test/unit/vfs/*.test.ts`'s
// in-memory fake provider. Matches M5's own stated acceptance criteria
// exactly: a write to a `deny-write` path fails from the bash tool (not an
// application-level tool); `ln -s` indirection around a rule-covered path
// fails; `mv` of a rule-covered directory fails; `hidden` paths are absent
// from `ls`.
//
// Gating and layout matches `test/e2e/workspace-mounts.e2e.ts` (M2.4) and
// `test/e2e/git-ssh-policy.e2e.ts` (M4.4) exactly: `vitest.config.ts` never
// matches `test/e2e/**`, so a plain `npm test` never touches this file, and
// `describe.skipIf` below additionally gates the whole suite on `CORB_E2E=1`.
// Run via `CORB_E2E=1 npx vitest run --config vitest.e2e.config.ts
// test/e2e/vfs-policy-from-bash.e2e.ts`, `npm run test:e2e`, or `make e2e`.
//
// Like `workspace-mounts.e2e.ts`, this suite drives `VM.create()` directly
// rather than `runSession()` — `runSession()` launches Pi's interactive TUI
// attached to real stdio, not scriptable for an automated assertion, the
// same reasoning every e2e suite in this codebase shares (see that file's
// own module comment for the fuller argument). Every guest-side check below
// goes through `guestShell()`, a bare `/bin/sh -c <script>` exec'd through
// `dropcap` as the unprivileged `agent` uid — this *is* "the bash tool" the
// milestone's own accept-criteria wording means to distinguish from Pi's own
// Edit tool, not anything Pi-specific.
//
// This suite's whole point is proving `src/vm/session.ts`'s *current* mount-
// building loop (inside `runSession`) actually holds, so the mount
// construction below is copied from that loop's exact current shape —
// `withGlobPolicy(dir.mode === "ro" ? new ReadonlyProvider(base) : base, {
// rules: toGlobRules(name, rawRules), onDeny })` — rather than re-derived. A
// drift between this test's wiring and the real code's wiring must fail this
// suite, not silently diverge, matching every prior e2e file's own
// discipline for the one subsystem its own milestone changed. Only the `rw`
// branch is exercised (`dir.mode === "ro"` is never taken here) —
// `workspace-mounts.e2e.ts` already proved `ro` mounting itself works, and
// none of M5's four accept criteria are `ro`-specific.
//
// ---------------------------------------------------------------------------
// `globToRegExp("secrets/**")` also matches the bare directory name `secrets`
// ---------------------------------------------------------------------------
//
// Verified directly against `src/vfs/glob.ts`'s own `globToRegExp` before
// relying on it for the `hidden` rule below (getting this wrong would make
// the "hidden from `ls`" scenario assert against the wrong path):
// `globToRegExp("secrets/**").source` is `^secrets(?:\/[^/]+)*$` — the
// trailing `**` fragment `(?:\/[^/]+)*` allows *zero* iterations, so the
// regex matches the bare string `"secrets"` in addition to
// `"secrets/key.pem"`, `"secrets/a/b"`, etc. (and correctly rejects
// `"secretsxyz"`, since the literal segment `secrets` is whole-segment
// anchored). Confirmed interactively:
//
//   $ npx tsx -e "
//   import { globToRegExp } from './src/vfs/glob.ts';
//   const re = globToRegExp('secrets/**');
//   console.log(re.source);                  // ^secrets(?:\/[^/]+)*$
//   console.log(re.test('secrets'));         // true
//   console.log(re.test('secrets/key.pem')); // true
//   console.log(re.test('secretsxyz'));      // false
//   "
//
// This is also exactly what `test/unit/vfs/policy.test.ts`'s own
// `ruleMayMatchUnderDirectory` tests rely on (`{ glob: "secrets/**", mode:
// "hidden" }` against `ruleMayMatchUnderDirectory(rules, "secrets")` ===
// `true`, around line 190 of that file) and what `test/unit/vfs/glob.test.ts`
// documents for the two-sided `"**/secrets/**"` pattern (around line 26,
// matching the bare `"secrets"` too) — this suite's own `"secrets/**"` rule
// (no leading `**`, since there is nothing above the mount root to match) is
// the same one-sided case, confirmed the same way.
//
// A real, non-obvious *consequence* of this, discovered empirically while
// building this suite (see the next section): because the bare directory
// name `secrets` itself matches the `hidden` rule, a `mv secrets ...`
// attempt is denied via the plain per-path `hidden` -> `ENOENT` decision on
// `secrets` itself, *before* `withGlobPolicy`'s dedicated directory-rename
// subtree check (`ruleMayMatchUnderDirectory`, which is what surfaces
// `EACCES`) is ever reached — `src/vfs/glob-policy.ts`'s `rename()` decides
// the old path first, and a `hidden` match there throws immediately. So the
// `hidden`-covered `secrets` directory cannot be used to demonstrate the
// milestone's "`mv` of a rule-covered directory fails with `EACCES`, not
// `ENOENT`" criterion at all — it only ever demonstrates `ENOENT` (still a
// real denial, just the wrong errno for that specific criterion). This suite
// uses a *second*, separate directory (`vault/`, covered only by a
// `vault/*.pem` rule whose glob does not match the bare name `vault` itself)
// to exercise the dedicated `EACCES` subtree-rename path cleanly — see the
// "mv of a rule-covered directory" test below for the full reasoning.
//
// ---------------------------------------------------------------------------
// Symlink/hard-link indirection: two distinct real-VM behaviors, not one
// ---------------------------------------------------------------------------
//
// Before this suite existed, `src/vfs/glob-policy.ts`'s symlink-bypass
// defense (`resolveForRecheck`) had only ever been exercised against
// `test/unit/vfs/glob-policy.test.ts`'s in-memory fake provider, which calls
// `backend.symlink(...)` directly to set up fixture state — bypassing the
// policy wrapper entirely for *creation*, then testing only the wrapped
// *read* afterward. Driving the real `ln -s`/`ln` commands through a real
// guest kernel and a real `RealFSProvider` surfaced a real difference: guest
// symlink *creation* itself, not just a later read through it, can also be
// denied — depending on which rule mode the resolved target falls under.
// Confirmed empirically (a standalone scratch VM, discarded after use, with
// `onDeny` wired to `console.log` so every intercepted decision was visible):
//
//   - Target covered by a `hidden` rule (`secrets/key.pem`, via `secrets/**`):
//     `ln -s secrets/key.pem decoy` itself fails
//     (`ln: decoy: No such file or directory`), *before* any `cat` is ever
//     attempted. `withGlobPolicy`'s `symlink()` now resolves what the target
//     would point to and checks it against the `stat` category *before ever
//     calling the real backend's own `symlink()`* (`checkSymlinkTargetPolicy`
//     in `src/vfs/glob-policy.ts`), so the observed `onDeny` event fires at
//     that point: `{"path":"secrets/key.pem","op":"stat",...,"reason":"hidden
//     (symlink target resolves into a policy-denied path)"}`, and no real
//     symlink object is ever created on the host backend (confirmed via a
//     direct host-side `fs.existsSync` check in that scratch VM).
//
//     This was *not* always true: earlier, this same case was denied only by
//     the RPC layer's own post-creation `lstat`/`getattr` fetch on the
//     just-created symlink (needed to populate the FUSE reply's attributes),
//     which happens *after* the real backend's `symlink()` had already
//     succeeded — leaving a real, inaccessible symlink object on the host
//     that the RPC service's own ino-tracking never learned about (its
//     `ensureIno`/`invalidateReaddirCacheEntries` calls, one line after that
//     `lstat`, were never reached). That was not just a cosmetic discrepancy:
//     confirmed via a second scratch-VM boot that once that orphaned entry's
//     parent directory's `readdirCache` entry naturally expired
//     (`READDIR_CACHE_TTL_MS`, 5s of guest inactivity) and a fresh `readdir`
//     re-enumerated it, every subsequent `ls` of that directory returned
//     permanently empty (0 bytes, exit 0, did not self-heal) until VM
//     recreation — see `src/vfs/glob-policy.ts`'s own `checkSymlinkTargetPolicy`
//     doc comment for the full mechanism and the fix. The "hidden: ... ls"
//     test below no longer needs to run before the symlink/hard-link/`mv`
//     scenarios for this reason — re-confirmed via a fresh VM boot running
//     the exact denied-ops-without-`ls` sequence that used to trigger it.
//   - Target covered by a `deny-read` rule (`readable-secret.txt`): creation
//     succeeds cleanly (`TABLE.stat.deny-read` is `ALLOW`, so the same
//     post-creation getattr is not denied), and it is the *subsequent*
//     `cat` that fails — but via a `readlink` denial, not a `read`/`open`
//     denial: the observed event was `{"path":"decoy",...,"op":"readlink",
//     "reason":"... (via resolved path 'readable-secret.txt')"}`. The guest
//     kernel resolves an in-mount relative symlink target itself (via its own
//     `readlink()` FUSE request against the *symlink's own path*, not a
//     brand-new `open()` against the resolved target), and `withGlobPolicy`'s
//     `readlink()` wrapper applies the same resolved-path recheck as every
//     other gated operation — so the denial happens one level earlier in the
//     resolution chain than "an `open()` for the resolved path was denied"
//     would suggest, though the guest-visible outcome (`cat` fails, no
//     content is ever disclosed) is exactly what the milestone's accept
//     criterion requires either way.
//
// Both are real, and both are exercised below as two separate scenarios
// rather than picked apart into "the one true way `ln -s` fails" — the
// milestone's own accept-criteria wording ("`ln -s` indirection... fails...
// (or as two separate commands so you can tell which step actually failed)")
// already anticipated that either step could be the one that denies,
// depending on the target's rule mode.
//
// The hard-link scenario (`ln secrets/key.pem decoy-hardlink`) is simpler and
// was confirmed to behave exactly as designed: `link()`'s own wrapper gates
// the *existing* endpoint directly (`decide("link", ..., existingNorm,
// false)`) before ever calling the real backend, so the hidden source is
// denied immediately, no real link is ever created on the host (confirmed via
// `fs.existsSync` on the host), and no resolved-path recheck is even needed
// for this case — the existing endpoint's own literal path already matches
// the rule.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHttpHooks, RealFSProvider, VM, type VirtualProvider } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { publicWorkspacePath, rawWorkspacePath, toGlobRules } from "../../src/vm/session.ts";
import { withGlobPolicy, type GlobPolicyDenyEvent } from "../../src/vfs/glob-policy.ts";
import { createAuditWriter, type AuditEvent, type AuditWriter } from "../../src/policy/audit.ts";
import type { DirRuleConfig } from "../../src/config/load.ts";

// Matches `image/corb-image.json`'s `postBuild.commands` and
// `image/verify.ts`'s own hardcoded convention, exactly like the other e2e
// suites — not read dynamically from `/etc/corb/image.json` here, see those
// suites' own module comments for why.
const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";

// No login shell for any exec (array-form `exec` runs none), matching
// `image/verify.ts`'s own `BASE_PATH` convention.
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const DIR_NAME = "rw";

const FROZEN_FILE_NAME = "frozen.txt";
const FROZEN_CONTENT = "do not touch\n";

const SECRET_FILE_CONTENT = "topsecret\n";
const VAULT_FILE_CONTENT = "vault master credential\n";
const DENY_READ_CONTENT = "denyread-content\n";
const READABLE_SECRET_NAME = "readable-secret.txt";

const SESSION_ID = "corb-e2e-vfs-policy-from-bash-session";
const SESSION_LABEL = "corb-e2e-vfs-policy-from-bash";

describe.skipIf(!process.env.CORB_E2E)("vfs-policy-from-bash e2e (real VM boot)", () => {
  let hostDir: string;
  let auditPath: string;
  let audit: AuditWriter;
  let vm: VM | undefined;

  beforeAll(async () => {
    hostDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-vfs-policy-"));
    fs.writeFileSync(path.join(hostDir, FROZEN_FILE_NAME), FROZEN_CONTENT);
    fs.mkdirSync(path.join(hostDir, "secrets"));
    fs.writeFileSync(path.join(hostDir, "secrets", "key.pem"), SECRET_FILE_CONTENT);
    fs.mkdirSync(path.join(hostDir, "vault"));
    fs.writeFileSync(path.join(hostDir, "vault", "master.pem"), VAULT_FILE_CONTENT);
    fs.writeFileSync(path.join(hostDir, READABLE_SECRET_NAME), DENY_READ_CONTENT);

    const tmpAuditDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-vfs-policy-audit-"));
    auditPath = path.join(tmpAuditDir, "audit.jsonl");
    audit = createAuditWriter({ path: auditPath });

    const resolvedImage = resolveRuntimeImage();
    const { httpHooks, env } = createHttpHooks({ allowedHosts: [], allowedInternalHosts: [] });

    const rawRules: DirRuleConfig[] = [
      { glob: FROZEN_FILE_NAME, mode: "deny-write", reason: "frozen file, read-only for this session" },
      { glob: "secrets/**", mode: "hidden", reason: "no secrets exposed to the guest" },
      // Deliberately does *not* match the bare directory name `vault` itself
      // (the pattern requires a second, `.pem`-suffixed segment) — see the
      // module comment's "consequence" section for why this suite needs a
      // second, separately-covered directory distinct from `secrets` to
      // exercise the dedicated EACCES directory-rename-subtree path rather
      // than `hidden`'s own direct ENOENT.
      { glob: "vault/*.pem", mode: "deny-write", reason: "vault credentials, read-only for this session" },
      { glob: READABLE_SECRET_NAME, mode: "deny-read", reason: "content must never be disclosed to the guest" },
    ];

    const onVfsDeny = (event: GlobPolicyDenyEvent): void => {
      const subject = event.path === "" ? event.op : `${event.op} ${event.path}`;
      const reason =
        event.outcome.kind === "shadowed"
          ? `shadowed (redirected to ephemeral storage): ${event.reason}`
          : event.reason;
      audit.record({ channel: "vfs", decision: "deny", subject, reason, sessionId: SESSION_ID });
    };

    // Exactly `src/vm/session.ts`'s own current mount-building loop (inside
    // `runSession`), for this one directory: `dir.mode === "rw"` here, so
    // `base` is used unwrapped (never `ReadonlyProvider`) — see the module
    // comment for why only the `rw` branch needs exercising in this suite.
    const base: VirtualProvider = new RealFSProvider(hostDir);
    const vfsMounts: Record<string, VirtualProvider> = {
      [rawWorkspacePath(DIR_NAME)]: withGlobPolicy(base, { rules: toGlobRules(DIR_NAME, rawRules), onDeny: onVfsDeny }),
    };

    vm = await VM.create({
      sandbox: { imagePath: resolvedImage.assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks,
      env,
      vfs: { mounts: vfsMounts },
      sessionLabel: SESSION_LABEL,
    });
  }, 180_000);

  afterAll(async () => {
    try {
      if (vm) {
        await vm.close();
      }
    } finally {
      audit?.flush();
      fs.rmSync(hostDir, { recursive: true, force: true });
      if (auditPath) {
        fs.rmSync(path.dirname(auditPath), { recursive: true, force: true });
      }
    }
  }, 180_000);

  function requireVm(): VM {
    if (!vm) {
      throw new Error("vfs-policy-from-bash e2e: VM was not booted (beforeAll must have failed)");
    }
    return vm;
  }

  /** Runs a shell script as the dropped-privilege `agent` uid via `dropcap`, mirroring every other e2e suite's `guestShell` helper. Always runs with cwd at the mounted directory's public path. */
  async function guestShell(script: string) {
    return requireVm().exec(
      [DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh", "-c", `cd ${publicWorkspacePath(DIR_NAME)} && ${script}`],
      {
        env: { PATH: BASE_PATH },
        stdout: "buffer",
        stderr: "buffer",
      },
    );
  }

  it("sanity: the workspace directory is mounted and the frozen fixture is visible by name", async () => {
    const result = await guestShell(`test -f ${FROZEN_FILE_NAME} && echo MOUNT_OK`);
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout).toContain("MOUNT_OK");
  });

  it("deny-write: a write to a deny-write path fails from the bash tool, and the host file is unchanged", async () => {
    const result = await guestShell(`echo overwrite >> ${FROZEN_FILE_NAME}`);
    expect(result.ok, "a write to a deny-write path unexpectedly succeeded").toBe(false);

    const hostContent = fs.readFileSync(path.join(hostDir, FROZEN_FILE_NAME), "utf8");
    expect(hostContent, "the host file's content changed despite the write being denied").toBe(FROZEN_CONTENT);
  });

  // No longer a load-bearing ordering constraint — see the module comment's
  // "Symlink/hard-link indirection" section above for the full history. This
  // test was originally required to run *before* any of the symlink/hard-
  // link/`mv` scenarios below: issuing several consecutive denied mutating
  // guest operations (a denied `ln -s` into a hidden path, a denied hard
  // link, a denied `mv`) *without* an intervening `ls` used to leave a real,
  // RPC-service-ino-less symlink entry orphaned on the backend (created by
  // `provider.symlink()` before the *following* `lstat` denied it), which
  // corrupted every subsequent `ls` of this directory to completely empty
  // (`exit 0`, zero bytes) once that directory's readdir cache next expired
  // — not a guest-kernel caching quirk, as originally guessed, but a real
  // bug in `src/vfs/glob-policy.ts`'s `symlink()` (fixed: it now checks the
  // resolved target's policy *before* ever calling the real backend's own
  // `symlink()`, so no orphaned entry is created in the first place).
  // Re-verified with a fresh VM boot running this exact denied-ops-without-
  // `ls` sequence after the fix: `ls` stays correct throughout, including
  // after an idle gap long enough for the readdir cache to expire. This
  // test's own position relative to the others below is no longer load-
  // bearing, but is left unchanged rather than reordered as a separate,
  // unrelated diff.
  it("hidden: the secrets directory is absent from ls, while unrelated fixtures remain listed", async () => {
    const result = await guestShell(`ls -a .`);
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    const names = result.stdout.split(/\s+/).filter((s) => s.length > 0);
    expect(names, `ls output unexpectedly lists 'secrets': ${result.stdout}`).not.toContain("secrets");
    expect(names, `ls output should still list '${FROZEN_FILE_NAME}': ${result.stdout}`).toContain(FROZEN_FILE_NAME);
    expect(names, `ls output should still list 'vault': ${result.stdout}`).toContain("vault");
    expect(names, `ls output should still list '${READABLE_SECRET_NAME}': ${result.stdout}`).toContain(READABLE_SECRET_NAME);
  });

  it("ln -s indirection into a hidden path: symlink creation itself is denied, and no content is ever disclosed", async () => {
    const linkResult = await guestShell(`ln -s secrets/key.pem decoy-hidden-symlink`);
    // See the module comment: for a `hidden`-covered target, the RPC layer's
    // own post-creation attribute fetch on the new symlink is itself denied
    // (`TABLE.stat.hidden` is `ENOENT`), so creation fails outright — verified
    // empirically, not assumed.
    expect(linkResult.ok, "creating a symlink that resolves into a hidden path unexpectedly succeeded").toBe(false);
    expect(linkResult.stdout + linkResult.stderr).not.toContain(SECRET_FILE_CONTENT.trim());

    // A real symlink object can still land on the host backend despite the
    // guest-visible failure (see the module comment) — documented here, not
    // hidden: the point of this assertion is that it is permanently
    // inaccessible from the guest, not that the host is byte-for-byte
    // pristine. A follow-up `ls` must never reveal the name, and a follow-up
    // `cat` (in case some other path managed to create it) must never
    // succeed either.
    const lsResult = await guestShell(`ls -a .`);
    expect(lsResult.ok, `exit ${lsResult.exitCode}: ${lsResult.stderr}`).toBe(true);
    expect(lsResult.stdout, "the guest can see the decoy symlink's name after a denied creation").not.toContain("decoy-hidden-symlink");

    const catResult = await guestShell(`cat decoy-hidden-symlink 2>/dev/null`);
    expect(catResult.ok, "reading the decoy name unexpectedly succeeded").toBe(false);
    expect(catResult.stdout).not.toContain(SECRET_FILE_CONTENT.trim());
  });

  it("ln -s indirection into a deny-read path: creation succeeds, but the resolved-path recheck denies the read", async () => {
    const linkResult = await guestShell(`ln -s ${READABLE_SECRET_NAME} decoy-denyread-symlink`);
    expect(linkResult.ok, `creating the symlink itself unexpectedly failed: exit ${linkResult.exitCode}: ${linkResult.stderr}`).toBe(
      true,
    );

    const readResult = await guestShell(`cat decoy-denyread-symlink`);
    expect(readResult.ok, "reading through a symlink that resolves into a deny-read path unexpectedly succeeded").toBe(false);
    expect(readResult.stdout).not.toContain(DENY_READ_CONTENT.trim());
  });

  it("hard-link indirection: ln of the hidden path to a new name is denied (existing endpoint gated directly, no real link created)", async () => {
    const linkResult = await guestShell(`ln secrets/key.pem decoy-hardlink`);
    expect(linkResult.ok, "hard-linking a hidden path to a new name unexpectedly succeeded").toBe(false);
    expect(fs.existsSync(path.join(hostDir, "decoy-hardlink")), "a real hard link was created on the host despite the denial").toBe(
      false,
    );

    // Belt and suspenders: even if the link call had somehow gone through,
    // there must be no way to read the secret content back out under the new
    // name.
    const readResult = await guestShell(`cat decoy-hardlink 2>/dev/null`);
    expect(readResult.ok, "reading through a hard link to a hidden path unexpectedly succeeded").toBe(false);
  });

  it("mv of a rule-covered directory fails with EACCES, and the directory is not actually renamed", async () => {
    // Uses `vault/`, not `secrets/` — see the module comment's "consequence"
    // section for why `secrets` (whose bare name is itself `hidden`) cannot
    // demonstrate this specific EACCES-not-ENOENT criterion.
    const result = await guestShell(`mv vault vault-moved 2>&1`);
    expect(result.ok, "renaming a rule-covered directory unexpectedly succeeded").toBe(false);
    // `docs/design.md` §3 / `src/vfs/policy.ts`'s directory-rename subtree
    // check surfaces this uniformly as `EACCES` across every mode, distinct
    // from `hidden`'s own normal `ENOENT` for direct access to a covered path
    // — asserted on the guest-visible error text (BusyBox `mv`'s own
    // errno-derived message), not just a bare non-zero exit. Confirmed
    // empirically: BusyBox `mv` prints exactly "mv: can't rename 'vault':
    // Permission denied" for this case.
    expect(result.stdout + result.stderr).toMatch(/Permission denied/i);

    expect(fs.existsSync(path.join(hostDir, "vault")), "the directory was actually renamed on the host despite the denial").toBe(true);
    expect(fs.existsSync(path.join(hostDir, "vault-moved")), "a new 'vault-moved' directory appeared on the host").toBe(false);
    expect(fs.readFileSync(path.join(hostDir, "vault", "master.pem"), "utf8")).toBe(VAULT_FILE_CONTENT);
  });

  it("audit log: real channel=vfs, decision=deny entries for every denial scenario above are on disk after flush()", () => {
    audit.flush();
    expect(fs.existsSync(auditPath)).toBe(true);
    const lines = fs
      .readFileSync(auditPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);

    const denyWrite = lines.find(
      (event) =>
        event.channel === "vfs" &&
        event.decision === "deny" &&
        event.subject === `write ${FROZEN_FILE_NAME}` &&
        event.reason?.includes("frozen file, read-only for this session"),
    );
    expect(denyWrite, `no matching vfs/deny entry for the frozen-file write in: ${JSON.stringify(lines)}`).toBeDefined();
    expect(denyWrite?.sessionId).toBe(SESSION_ID);

    const denySecrets = lines.find(
      (event) => event.channel === "vfs" && event.decision === "deny" && (event.subject.includes("secrets") || event.reason?.includes("secrets")),
    );
    expect(denySecrets, `no matching vfs/deny entry mentioning 'secrets' in: ${JSON.stringify(lines)}`).toBeDefined();

    const denyVaultRename = lines.find(
      (event) => event.channel === "vfs" && event.decision === "deny" && event.subject === "rename vault",
    );
    expect(denyVaultRename, `no matching vfs/deny entry for the vault directory rename in: ${JSON.stringify(lines)}`).toBeDefined();
    expect(denyVaultRename?.reason).toContain("relocate a rule-matched subtree");

    const denyReadableSecret = lines.find(
      (event) => event.channel === "vfs" && event.decision === "deny" && event.reason?.includes(READABLE_SECRET_NAME),
    );
    expect(denyReadableSecret, `no matching vfs/deny entry mentioning '${READABLE_SECRET_NAME}' in: ${JSON.stringify(lines)}`).toBeDefined();
  });
});
