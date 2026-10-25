import { describe, expect, it } from "vitest";
import { builtinGitRules } from "../../../src/config/gitprotect.ts";
import { toGlobRules } from "../../../src/vm/session.ts";
import { matchRule, ruleMayMatchUnderDirectory } from "../../../src/vfs/policy.ts";
import { withGlobPolicy } from "../../../src/vfs/glob-policy.ts";
import { FakeVirtualProvider } from "../../fakes/provider.ts";

describe("config/gitprotect", () => {
  const rules = toGlobRules("repo", builtinGitRules());

  it("returns the fixed, ordered deny-write rules with a stable reason", () => {
    expect(builtinGitRules()).toEqual([
      ".git",
      ".git/config*",
      ".git/commondir",
      ".git/hooks/**",
      ".git/worktrees/*/commondir",
      ".git/worktrees/*/config*",
      ".git/modules/**/config*",
      ".git/modules/**/commondir",
      ".git/modules/**/hooks/**",
    ].map((glob) => ({ glob, mode: "deny-write", reason: "protect host Git metadata" })));
    const changed = builtinGitRules();
    changed[0]!.reason = "changed";
    expect(builtinGitRules()[0]!.reason).toBe("protect host Git metadata");
  });

  it.each([
    ".git", ".git/config", ".git/config.lock", ".git/config.worktree", ".git/commondir",
    ".git/hooks", ".git/hooks/pre-commit", ".git/hooks/nested/hook",
    ".git/worktrees/other/commondir", ".git/worktrees/other/config", ".git/worktrees/other/config.lock",
    ".git/modules/a/config", ".git/modules/a/config.lock", ".git/modules/a/commondir",
    ".git/modules/a/hooks/pre-commit", ".git/modules/a/modules/b/config",
    ".git/modules/a/refs/heads/config", ".git/modules/a/modules/b/commondir",
    ".git/modules/a/modules/b/hooks/pre-commit",
  ])("protects %s", (target) => {
    expect(matchRule(rules, target)?.mode).toBe("deny-write");
  });

  it.each([
    "src/index.ts", "nested/.git/config", "sub/.git", ".githooks/pre-commit", ".husky/pre-commit",
    ".git/index", ".git/index.lock", ".git/HEAD", ".git/refs/heads/main", ".git/objects/pack/new.pack",
    ".git/logs/HEAD", ".git/rebase-merge/done",
  ])("leaves %s writable", (target) => {
    expect(matchRule(rules, target)).toBeUndefined();
  });

  it.each(["src", ".git/refs", ".git/objects/pack", ".git/logs", ".git/rebase-merge"])(
    "permits renaming %s and unrelated destinations",
    async (directory) => {
      expect(ruleMayMatchUnderDirectory(rules, directory)).toBe(false);
      const backend = new FakeVirtualProvider();
      await backend.mkdir(`/${directory}`, { recursive: true });
      const wrapped = withGlobPolicy(backend, { rules });
      await expect(wrapped.rename(`/${directory}`, `/${directory}-renamed`)).resolves.toBeUndefined();
    },
  );

  it("permits git's index.lock creation and rename onto index", async () => {
    const backend = new FakeVirtualProvider();
    await backend.mkdir("/.git");
    await backend.writeFile("/.git/index", "old");
    const wrapped = withGlobPolicy(backend, { rules });
    await wrapped.writeFile("/.git/index.lock", "new");
    await wrapped.rename("/.git/index.lock", "/.git/index");
    expect(await backend.readFile("/.git/index", { encoding: "utf8" })).toBe("new");
    expect(backend.existsSync("/.git/index.lock")).toBe(false);
  });
});
