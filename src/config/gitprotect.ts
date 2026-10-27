import type { DirRuleConfig } from "./load.ts";

const GIT_PROTECTION_GLOBS = [
  ".git",
  ".git/config*",
  ".git/commondir",
  ".git/hooks/**",
  ".git/worktrees/*/commondir",
  ".git/worktrees/*/config*",
  ".git/modules/**/config*",
  ".git/modules/**/commondir",
  ".git/modules/**/hooks/**",
] as const;

/** Keep the order and reason stable: trust records compare both. */
export function builtinGitRules(): DirRuleConfig[] {
  return GIT_PROTECTION_GLOBS.map((glob) => ({ glob, mode: glob.endsWith("config*") ? "copy-on-write" : "deny-write", reason: "protect host Git metadata" }));
}
