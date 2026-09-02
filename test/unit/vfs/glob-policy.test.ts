// Unit tests for `src/vfs/glob-policy.ts` — M5.3. Exercises `withGlobPolicy`
// against `test/fakes/provider.ts` (never a real `RealFSProvider`/real VM —
// that is M5.5's job), covering the top-level plan's §8 adversarial battery
// ("symlink indirection, hardlink aliasing, directory rename, rename-into-
// denied, `//` joins, unknown-method fail-closed") plus at least one
// representative case per `RuleMode` per major operation category, proving
// the wiring between `src/vfs/policy.ts`'s pure decisions and real
// Proxy-intercepted calls is correct — the pure table itself is already
// covered by `test/unit/vfs/policy.test.ts` (M5.2), so this file does not
// re-litigate it, only the plumbing on top of it.
import { constants as fsConstants } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { FakeVirtualProvider } from "../../fakes/provider.ts";
import { withGlobPolicy, type GlobPolicyDenyEvent } from "../../../src/vfs/glob-policy.ts";
import type { GlobRule } from "../../../src/vfs/policy.ts";
import type { RuleMode } from "../../../src/config/schema.ts";

function setup(rules: GlobRule[]) {
  const backend = new FakeVirtualProvider();
  const denies: GlobPolicyDenyEvent[] = [];
  const wrapped = withGlobPolicy(backend, { rules, onDeny: (event) => denies.push(event) });
  return { backend, wrapped, denies };
}

async function expectErrno(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code });
}

// ---------------------------------------------------------------------------
// The three "holes" design.md calls out by name
// ---------------------------------------------------------------------------

describe("withGlobPolicy: symlink-bypass defense", () => {
  it("denies `ln -s <deny-read-path> decoy && cat decoy` — the literal request path matches no rule, but its resolved target does", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "deny-read", reason: "secret" }];
    const { backend, wrapped, denies } = setup(rules);
    await backend.writeFile("/secret.txt", "sssh");
    await backend.symlink("secret.txt", "/decoy");

    await expectErrno(wrapped.readFile("/decoy"), "EACCES");
    expect(denies.at(-1)?.reason).toContain("via resolved path");
  });

  it("denies open() for read through the same symlink indirection", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "hidden", reason: "secret" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/secret.txt", "sssh");
    await backend.symlink("secret.txt", "/decoy");

    await expectErrno(wrapped.open("/decoy", "r"), "ENOENT");
  });

  it("does not deny a symlink whose target is unrelated to any rule", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "deny-read", reason: "secret" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/ordinary.txt", "hello");
    await backend.symlink("ordinary.txt", "/decoy");

    await expect(wrapped.readFile("/decoy")).resolves.toEqual(Buffer.from("hello"));
  });

  it("fails closed (denies) when realpath cannot resolve the path for a reason other than ENOENT (a symlink loop)", async () => {
    const rules: GlobRule[] = [];
    const { backend, wrapped, denies } = setup(rules);
    await backend.symlink("/b", "/a");
    await backend.symlink("/a", "/b");

    await expectErrno(wrapped.stat("/a"), "EACCES");
    expect(denies.at(-1)?.reason).toContain("failing closed");
  });

  it("does not deny a create-path operation whose parent directory legitimately does not exist yet (ENOENT is expected and skipped)", async () => {
    const rules: GlobRule[] = [];
    const { wrapped } = setup(rules);
    // No rule at all, and the parent ("/missing") doesn't exist — realpath on
    // the parent throws ENOENT, which must be treated as "no information
    // gained", not a policy denial; the real, unrelated ENOENT from actually
    // trying to open inside a missing directory is what should surface.
    await expectErrno(wrapped.open("/missing/newfile", "w"), "ENOENT");
  });

  it("resolves a symlinked ancestor directory before checking a create-path operation, per docs/design.md §3's 'or of its parent' rule", async () => {
    const rules: GlobRule[] = [{ glob: "hidden-dir/**", mode: "hidden", reason: "hidden tree" }];
    const { backend, wrapped } = setup(rules);
    await backend.mkdir("/hidden-dir");
    await backend.symlink("hidden-dir", "/decoy-dir");

    // The literal request path "decoy-dir/newfile" matches no rule, but
    // "/decoy-dir" resolves (via realpath of the parent) to "/hidden-dir",
    // whose subtree is hidden.
    await expectErrno(wrapped.open("/decoy-dir/newfile", "w"), "ENOENT");
  });
});

// ---------------------------------------------------------------------------
// docs/adr/0011-close-open-race-with-resolved-path.md: `decide()` used to
// resolve a path purely to *decide*, then every call site issued the real
// backend operation against the original, unresolved path anyway — leaving a
// TOCTOU window between the policy check and the backend's own re-resolution.
// These tests assert *which path argument the backend actually receives*
// (via `vi.spyOn`), per that ADR's own testing rationale: a timing-dependent
// simulated race would be flaky and prove less than pinning the argument
// itself. Every case here uses a symlink `/decoy(-dir)` pointing at a real
// `/real(-dir)` entry.
// ---------------------------------------------------------------------------

describe("withGlobPolicy: resolved-path redirect closes the check-then-use race (positive cases)", () => {
  it("open() for read routes the backend call through the already-resolved path, not the symlink name", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hello");
    await backend.symlink("/real.txt", "/decoy");
    const openSpy = vi.spyOn(backend, "open");

    await wrapped.open("/decoy", "r");

    expect(openSpy.mock.calls[0]?.[0]).toBe("/real.txt");
  });

  it("open() for write/create routes the backend call through the already-resolved parent, with the literal leaf reattached", async () => {
    const { backend, wrapped } = setup([]);
    await backend.mkdir("/real-dir");
    await backend.symlink("/real-dir", "/decoy-dir");
    const openSpy = vi.spyOn(backend, "open");

    await wrapped.open("/decoy-dir/newfile.txt", "w");

    // Only the parent was resolved — the literal leaf name is reattached
    // unchanged, exactly like every other create-path operation.
    expect(openSpy.mock.calls[0]?.[0]).toBe("/real-dir/newfile.txt");
  });

  it("stat() routes the backend call through the already-resolved path", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hi");
    await backend.symlink("/real.txt", "/decoy");
    const statSpy = vi.spyOn(backend, "stat");

    await wrapped.stat("/decoy");

    expect(statSpy.mock.calls[0]?.[0]).toBe("/real.txt");
  });

  it("access() routes the backend call through the already-resolved path", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hi");
    await backend.symlink("/real.txt", "/decoy");
    const accessSpy = vi.spyOn(backend, "access");

    await wrapped.access("/decoy");

    expect(accessSpy.mock.calls[0]?.[0]).toBe("/real.txt");
  });

  it("readFile() routes the backend call through the already-resolved path — the exact `cat decoy` scenario this ADR closes", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "sssh");
    await backend.symlink("/real.txt", "/decoy");
    const readFileSpy = vi.spyOn(backend, "readFile");

    await wrapped.readFile("/decoy");

    expect(readFileSpy.mock.calls[0]?.[0]).toBe("/real.txt");
  });

  it("readdir() routes the backend's own listing call through the resolved directory, while entry-hiding still uses the requested directory's rule path", async () => {
    // The `hidden` rule is keyed on "decoy-dir/secret.txt" — the *symlink's*
    // own apparent path — not "real-dir/secret.txt". If entry-hiding were
    // ever switched to use the resolved directory's rule path instead, this
    // rule would stop matching and "secret.txt" would leak into the listing.
    const rules: GlobRule[] = [{ glob: "decoy-dir/secret.txt", mode: "hidden", reason: "hidden via the symlink's own apparent path" }];
    const { backend, wrapped } = setup(rules);
    await backend.mkdir("/real-dir");
    await backend.writeFile("/real-dir/secret.txt", "x");
    await backend.writeFile("/real-dir/visible.txt", "y");
    await backend.symlink("/real-dir", "/decoy-dir");
    const readdirSpy = vi.spyOn(backend, "readdir");

    const entries = await wrapped.readdir("/decoy-dir");

    expect(readdirSpy.mock.calls[0]?.[0]).toBe("/real-dir");
    expect(entries).toContain("visible.txt");
    expect(entries).not.toContain("secret.txt");
  });

  it("mkdir() routes the backend call through the already-resolved parent, with the literal leaf reattached", async () => {
    const { backend, wrapped } = setup([]);
    await backend.mkdir("/real-dir");
    await backend.symlink("/real-dir", "/decoy-dir");
    const mkdirSpy = vi.spyOn(backend, "mkdir");

    await wrapped.mkdir("/decoy-dir/newsub");

    expect(mkdirSpy.mock.calls[0]?.[0]).toBe("/real-dir/newsub");
  });
});

describe("withGlobPolicy: resolved-path redirect never touches symlink-preserving operations (negative/regression cases)", () => {
  it("unlink() acts on the literally-named entry, never a resolved target", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hi");
    await backend.symlink("/real.txt", "/decoy");
    const unlinkSpy = vi.spyOn(backend, "unlink");

    await wrapped.unlink("/decoy");

    expect(unlinkSpy.mock.calls[0]?.[0]).toBe("/decoy");
    // Only the symlink itself was removed — the real file it pointed to must
    // survive. Redirecting this to the resolved path would have deleted it.
    expect(backend.existsSync("/real.txt")).toBe(true);
  });

  it("lstat() acts on the literally-named entry, never a resolved target", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hi");
    await backend.symlink("/real.txt", "/decoy");
    const lstatSpy = vi.spyOn(backend, "lstat");

    const st = await wrapped.lstat("/decoy");

    expect(lstatSpy.mock.calls[0]?.[0]).toBe("/decoy");
    expect((st as { isSymbolicLink(): boolean }).isSymbolicLink()).toBe(true);
  });

  it("readlink() acts on the literally-named entry, never a resolved target", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hi");
    await backend.symlink("/real.txt", "/decoy");
    const readlinkSpy = vi.spyOn(backend, "readlink");

    await wrapped.readlink("/decoy");

    expect(readlinkSpy.mock.calls[0]?.[0]).toBe("/decoy");
  });

  it("rename()'s source endpoint acts on the literally-named entry, never a resolved target", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hi");
    await backend.symlink("/real.txt", "/decoy");
    const renameSpy = vi.spyOn(backend, "rename");

    await wrapped.rename("/decoy", "/decoy-renamed");

    expect(renameSpy.mock.calls[0]?.[0]).toBe("/decoy");
    // The symlink itself was renamed — the real file it pointed to must
    // still be reachable at its original name, untouched.
    expect(backend.existsSync("/real.txt")).toBe(true);
  });

  it("link()'s existing endpoint acts on the literally-named entry, never a resolved target", async () => {
    const { backend, wrapped } = setup([]);
    await backend.writeFile("/real.txt", "hi");
    await backend.symlink("/real.txt", "/decoy");
    const linkSpy = vi.spyOn(backend, "link");

    await wrapped.link("/decoy", "/decoy-link");

    expect(linkSpy.mock.calls[0]?.[0]).toBe("/decoy");
  });
});

describe("withGlobPolicy: link()/symlink() gated at creation time, both endpoints", () => {
  it("denies link() when the existing (source) path is restricted", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "deny-write", reason: "frozen" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/secret.txt", "content");

    await expectErrno(wrapped.link("/secret.txt", "/decoy"), "EACCES");
  });

  it("denies link() when the new (destination) path is restricted", async () => {
    const rules: GlobRule[] = [{ glob: "decoy", mode: "deny-write", reason: "frozen destination" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/other.txt", "content");

    await expectErrno(wrapped.link("/other.txt", "/decoy"), "EACCES");
  });

  it("denies symlink(anything, deniedPath) — the new entry's own path is gated regardless of what the (here, nonexistent) target resolves to", async () => {
    const rules: GlobRule[] = [{ glob: "decoy", mode: "hidden", reason: "hidden name" }];
    const { wrapped } = setup(rules);

    await expectErrno(wrapped.symlink("/this/target/string/is/never/checked/../../..", "/decoy"), "ENOENT");
  });

  it("allows symlink() whose target string happens to look like a denied path, when the target's rule mode does not gate stat() (deny-read)", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "deny-read", reason: "secret" }];
    const { wrapped, backend } = setup(rules);

    // `TABLE.stat["deny-read"]` is `ALLOW` — creation succeeds cleanly, and
    // only a later `readFile`/`open` through this link would be denied (see
    // the "symlink-bypass defense" describe block above). This is the case
    // that must keep working even after the "hidden"-target pre-creation
    // check below is added: that check is scoped to the `stat` category
    // specifically, not to "target matches any rule at all."
    await expect(wrapped.symlink("secret.txt", "/ok-name")).resolves.toBeUndefined();
    expect(await backend.readlinkSync("/ok-name")).toBe("secret.txt");
  });

  it("denies symlink() creation itself (not just a later read) when the target resolves into a hidden path, and never creates a real backend entry", async () => {
    // Regression test for a real bug found while investigating M5.5's e2e
    // suite: `rpc-service.js`'s `handleSymlink` calls `provider.symlink()`
    // (previously allowed here, since only the new entry's own name was
    // checked) and only afterward calls `provider.lstat()` on the new entry
    // to build the FUSE reply — which is what used to deny a hidden target,
    // but *after* a real symlink had already been created on the backend.
    // That left a real, RPC-service-ino-less entry behind that corrupted the
    // guest-visible directory listing once its readdir cache entry expired
    // (confirmed empirically against a real VM boot, not just theorized).
    // `TABLE.stat["hidden"]` is `ENOENT`, so this must now be denied before
    // `backend.symlink()` is ever called at all.
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "hidden", reason: "secret" }];
    const { wrapped, backend } = setup(rules);
    await backend.writeFile("/secret.txt", "sssh");

    await expectErrno(wrapped.symlink("secret.txt", "/decoy"), "ENOENT");
    expect(backend.existsSync("/decoy")).toBe(false);
  });

  it("allows a dangling symlink whose target does not exist at all — a nonexistent target is not a policy concern", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "hidden", reason: "secret" }];
    const { wrapped } = setup(rules);

    await expect(wrapped.symlink("does-not-exist.txt", "/dangling")).resolves.toBeUndefined();
  });
});

describe("withGlobPolicy: directory rename subtree coverage", () => {
  it("denies renaming a directory that contains a rule-matched path, even when the directory's own exact path matches no rule", async () => {
    const rules: GlobRule[] = [{ glob: "**/secret.txt", mode: "hidden", reason: "hidden anywhere" }];
    const { backend, wrapped, denies } = setup(rules);
    await backend.mkdir("/project");
    await backend.writeFile("/project/secret.txt", "x");

    await expectErrno(wrapped.rename("/project", "/elsewhere"), "EACCES");
    expect(denies.at(-1)?.reason).toContain("subtree");
    expect(denies.at(-1)?.rule).toBeUndefined();
  });

  it("allows renaming a directory whose contents match no rule at all", async () => {
    // Deliberately a rule rooted under a *different*, non-matching literal
    // top-level segment ("other", not "project") — a leading `**` here
    // would (correctly, per `ruleMayMatchUnderDirectory`'s own conservative
    // design, already covered by `test/unit/vfs/policy.test.ts`) make every
    // directory rename look risky, since `**` can always be satisfied by
    // consuming the whole directory path. This test is about the case where
    // the pattern plainly cannot reach anything under the renamed directory
    // at all.
    const rules: GlobRule[] = [{ glob: "other/secret.txt", mode: "hidden", reason: "hidden elsewhere" }];
    const { backend, wrapped } = setup(rules);
    await backend.mkdir("/project");
    await backend.writeFile("/project/ordinary.txt", "x");

    await expect(wrapped.rename("/project", "/elsewhere")).resolves.toBeUndefined();
    expect(await backend.existsSync("/elsewhere/ordinary.txt")).toBe(true);
  });

  it("denies a rename whose destination is itself a denied path", async () => {
    const rules: GlobRule[] = [{ glob: "blocked.txt", mode: "deny-write", reason: "frozen" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/a.txt", "hi");

    await expectErrno(wrapped.rename("/a.txt", "/blocked.txt"), "EACCES");
  });

  it("does not run the subtree check against a rename source that doesn't exist — the real backend's own ENOENT surfaces instead", async () => {
    const rules: GlobRule[] = [{ glob: "**/secret.txt", mode: "hidden", reason: "hidden anywhere" }];
    const { wrapped } = setup(rules);

    await expectErrno(wrapped.rename("/does-not-exist", "/also-nowhere"), "ENOENT");
  });
});

// ---------------------------------------------------------------------------
// `//`-shaped readdir joins
// ---------------------------------------------------------------------------

describe("withGlobPolicy: readdir filtering", () => {
  it("filters a hidden entry out of a root-directory listing without a `//`-shaped join crashing or leaking it", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "hidden", reason: "hidden" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/secret.txt", "x");
    await backend.writeFile("/visible.txt", "y");

    const entries = await wrapped.readdir("/");
    expect(entries).toContain("visible.txt");
    expect(entries).not.toContain("secret.txt");
  });

  it("normalizes a raw `//`-shaped path before listing, and still filters correctly", async () => {
    const rules: GlobRule[] = [{ glob: "secret.txt", mode: "hidden", reason: "hidden" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/secret.txt", "x");
    await backend.writeFile("/visible.txt", "y");

    const entries = await wrapped.readdir("//");
    expect(entries).toEqual(["visible.txt"]);
  });

  it("filters a hidden entry out of a nested directory listing", async () => {
    const rules: GlobRule[] = [{ glob: "sub/secret.txt", mode: "hidden", reason: "hidden" }];
    const { backend, wrapped } = setup(rules);
    await backend.mkdir("/sub");
    await backend.writeFile("/sub/secret.txt", "x");
    await backend.writeFile("/sub/visible.txt", "y");

    const entries = await wrapped.readdir("/sub");
    expect(entries).toEqual(["visible.txt"]);
  });

  it("still lists a non-hidden restricted entry (deny-write is listed, only hidden is filtered)", async () => {
    const rules: GlobRule[] = [{ glob: "frozen.txt", mode: "deny-write", reason: "frozen" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/frozen.txt", "x");

    const entries = await wrapped.readdir("/");
    expect(entries).toContain("frozen.txt");
  });
});

// ---------------------------------------------------------------------------
// Unknown-method fail-closed default
// ---------------------------------------------------------------------------

describe("withGlobPolicy: unrecognized VirtualProvider members", () => {
  it("returns a function that throws EPERM, never undefined or a silent pass-through", () => {
    const { wrapped } = setup([]);
    const asAny = wrapped as unknown as Record<string, unknown>;
    const value = asAny["someFutureVfsOperationNotYetInvented"];
    expect(typeof value).toBe("function");
    expect(() => (value as () => unknown)()).toThrow(/EPERM/);
  });

  it("still exposes undefined for an optional VirtualProvider member the backend genuinely does not implement", () => {
    const { wrapped } = setup([]);
    const asAny = wrapped as unknown as Record<string, unknown>;
    // `FakeVirtualProvider` deliberately does not implement `internalModuleStat`.
    expect(asAny["internalModuleStat"]).toBeUndefined();
  });

  it("passes capability getters straight through, untouched", () => {
    const { wrapped, backend } = setup([]);
    expect(wrapped.readonly).toBe(backend.readonly);
    expect(wrapped.supportsSymlinks).toBe(backend.supportsSymlinks);
    expect(wrapped.supportsWatch).toBe(backend.supportsWatch);
  });
});

// ---------------------------------------------------------------------------
// shadow-write: appears to succeed, real backend untouched, read-after-write
// resolution (a genuine behavioral choice this item is responsible for
// resolving — see src/vfs/glob-policy.ts's module comment for the reasoning)
// ---------------------------------------------------------------------------

describe("withGlobPolicy: shadow-write", () => {
  it("a write to a shadow-write path appears to succeed, but the real backend is never modified", async () => {
    const rules: GlobRule[] = [{ glob: "shadowed.txt", mode: "shadow-write", reason: "ephemeral" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/shadowed.txt", "original");

    await expect(wrapped.writeFile("/shadowed.txt", "guest-written")).resolves.toBeUndefined();

    // The real backend, read directly (bypassing the wrapper), is untouched.
    expect(await backend.readFile("/shadowed.txt")).toEqual(Buffer.from("original"));
  });

  it("a subsequent read of the same shadow-write path reflects the untouched real backend, not the shadow-written content — this module's resolved read-after-write behavior", async () => {
    const rules: GlobRule[] = [{ glob: "shadowed.txt", mode: "shadow-write", reason: "ephemeral" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/shadowed.txt", "original");

    await wrapped.writeFile("/shadowed.txt", "guest-written");

    await expect(wrapped.readFile("/shadowed.txt")).resolves.toEqual(Buffer.from("original"));
  });

  it("mkdir/unlink under shadow-write appear to succeed even though the real backend never had a shadow-store counterpart to remove", async () => {
    const rules: GlobRule[] = [{ glob: "shadowed.txt", mode: "shadow-write", reason: "ephemeral" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/shadowed.txt", "still here");

    await expect(wrapped.unlink("/shadowed.txt")).resolves.toBeUndefined();
    // The real file was never touched — appears removed to the guest, still present for real.
    expect(backend.existsSync("/shadowed.txt")).toBe(true);
  });

  it("a shadow-write copy destination never reaches the real backend, and reading it back reports ENOENT (reads never consult the shadow store)", async () => {
    const rules: GlobRule[] = [{ glob: "dest.txt", mode: "shadow-write", reason: "ephemeral" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/src.txt", "copy me");

    await expect(wrapped.copyFile("/src.txt", "/dest.txt")).resolves.toBeUndefined();
    expect(backend.existsSync("/dest.txt")).toBe(false);
    await expectErrno(wrapped.readFile("/dest.txt"), "ENOENT");
  });

  it("renaming a directory containing only a shadow-write path is still denied outright (not shadowed) — docs/design.md §3's own reasoning for why this row is EACCES in every mode", async () => {
    const rules: GlobRule[] = [{ glob: "**/shadowed.txt", mode: "shadow-write", reason: "ephemeral" }];
    const { backend, wrapped } = setup(rules);
    await backend.mkdir("/project");
    await backend.writeFile("/project/shadowed.txt", "x");

    await expectErrno(wrapped.rename("/project", "/elsewhere"), "EACCES");
  });
});

// ---------------------------------------------------------------------------
// Full four-mode battery, exercised end-to-end through the real wrapper —
// one representative case per mode per major operation category (the pure
// table itself is M5.2's own test's job).
// ---------------------------------------------------------------------------

describe("withGlobPolicy: mode x operation wiring", () => {
  async function buildFixture(mode: RuleMode) {
    const rules: GlobRule[] = [
      { glob: "read.txt", mode, reason: "t" },
      { glob: "write.txt", mode, reason: "t" },
      { glob: "stat.txt", mode, reason: "t" },
      { glob: "mutate.txt", mode, reason: "t" },
      { glob: "rename-src.txt", mode, reason: "t" },
      { glob: "link-src.txt", mode, reason: "t" },
      { glob: "access.txt", mode, reason: "t" },
      { glob: "readlink-link", mode, reason: "t" },
      { glob: "exists.txt", mode, reason: "t" },
      { glob: "copy-src.txt", mode, reason: "t" },
      { glob: "copy-dest.txt", mode, reason: "t" },
      { glob: "realpath.txt", mode, reason: "t" },
    ];
    const backend = new FakeVirtualProvider();
    await backend.writeFile("/read.txt", "read-content");
    await backend.writeFile("/write.txt", "write-content");
    await backend.writeFile("/stat.txt", "stat-content");
    await backend.writeFile("/mutate.txt", "mutate-content");
    await backend.writeFile("/rename-src.txt", "rename-content");
    await backend.writeFile("/link-src.txt", "link-content");
    await backend.writeFile("/access.txt", "access-content");
    await backend.writeFile("/readlink-target.txt", "target-content");
    await backend.symlink("readlink-target.txt", "/readlink-link");
    await backend.writeFile("/exists.txt", "exists-content");
    await backend.writeFile("/copy-src.txt", "copy-content");
    await backend.writeFile("/realpath.txt", "realpath-content");
    const denies: GlobPolicyDenyEvent[] = [];
    const wrapped = withGlobPolicy(backend, { rules, onDeny: (e) => denies.push(e) });
    return { backend, wrapped, denies };
  }

  it("deny-write: read allowed, write/mutate/rename/link denied EACCES, stat/access-read/readlink/exists/realpath allowed, access-write denied", async () => {
    const { wrapped } = await buildFixture("deny-write");
    await expect(wrapped.readFile("/read.txt")).resolves.toEqual(Buffer.from("read-content"));
    await expectErrno(wrapped.writeFile("/write.txt", "x"), "EACCES");
    await expect(wrapped.stat("/stat.txt")).resolves.toBeDefined();
    await expectErrno(wrapped.unlink("/mutate.txt"), "EACCES");
    await expectErrno(wrapped.rename("/rename-src.txt", "/rename-dst.txt"), "EACCES");
    await expectErrno(wrapped.link("/link-src.txt", "/link-dst.txt"), "EACCES");
    await expect(wrapped.access("/access.txt", fsConstants.R_OK)).resolves.toBeUndefined();
    await expectErrno(wrapped.access("/access.txt", fsConstants.W_OK), "EACCES");
    await expect(wrapped.readlink("/readlink-link")).resolves.toBe("readlink-target.txt");
    await expect(wrapped.exists("/exists.txt")).resolves.toBe(true);
    await expectErrno(wrapped.copyFile("/copy-src.txt", "/copy-dest.txt"), "EACCES");
    await expect(wrapped.realpath("/realpath.txt")).resolves.toBe("/realpath.txt");
  });

  it("deny-read: read/write/mutate/rename/link/access-read/readlink/copy-dest denied EACCES, stat/access-exists/exists/realpath allowed", async () => {
    const { wrapped } = await buildFixture("deny-read");
    await expectErrno(wrapped.readFile("/read.txt"), "EACCES");
    await expectErrno(wrapped.writeFile("/write.txt", "x"), "EACCES");
    await expect(wrapped.stat("/stat.txt")).resolves.toBeDefined();
    await expectErrno(wrapped.unlink("/mutate.txt"), "EACCES");
    await expectErrno(wrapped.rename("/rename-src.txt", "/rename-dst.txt"), "EACCES");
    await expectErrno(wrapped.link("/link-src.txt", "/link-dst.txt"), "EACCES");
    await expectErrno(wrapped.access("/access.txt", fsConstants.R_OK), "EACCES");
    await expect(wrapped.access("/access.txt", fsConstants.F_OK)).resolves.toBeUndefined();
    await expectErrno(wrapped.readlink("/readlink-link"), "EACCES");
    await expect(wrapped.exists("/exists.txt")).resolves.toBe(true);
    await expectErrno(wrapped.copyFile("/copy-src.txt", "/copy-dest.txt"), "EACCES");
    await expect(wrapped.realpath("/realpath.txt")).resolves.toBe("/realpath.txt");
  });

  it("hidden: everything reports ENOENT (or false for exists), and the entry is filtered from readdir", async () => {
    const { wrapped } = await buildFixture("hidden");
    await expectErrno(wrapped.readFile("/read.txt"), "ENOENT");
    await expectErrno(wrapped.writeFile("/write.txt", "x"), "ENOENT");
    await expectErrno(wrapped.stat("/stat.txt"), "ENOENT");
    await expectErrno(wrapped.unlink("/mutate.txt"), "ENOENT");
    await expectErrno(wrapped.rename("/rename-src.txt", "/rename-dst.txt"), "ENOENT");
    await expectErrno(wrapped.link("/link-src.txt", "/link-dst.txt"), "ENOENT");
    await expectErrno(wrapped.access("/access.txt", fsConstants.F_OK), "ENOENT");
    await expectErrno(wrapped.readlink("/readlink-link"), "ENOENT");
    await expect(wrapped.exists("/exists.txt")).resolves.toBe(false);
    await expectErrno(wrapped.copyFile("/copy-src.txt", "/copy-dest.txt"), "ENOENT");
    await expectErrno(wrapped.realpath("/realpath.txt"), "ENOENT");
    const entries = await wrapped.readdir("/");
    expect(entries).not.toContain("stat.txt");
  });

  it("shadow-write: read/stat/access/readlink/exists/realpath allowed against the real backend; write/mutate/rename/link/copy-dest shadowed (succeed without a throw, real backend untouched)", async () => {
    const { backend, wrapped } = await buildFixture("shadow-write");
    await expect(wrapped.readFile("/read.txt")).resolves.toEqual(Buffer.from("read-content"));
    await expect(wrapped.writeFile("/write.txt", "guest-write")).resolves.toBeUndefined();
    expect(await backend.readFile("/write.txt")).toEqual(Buffer.from("write-content"));
    await expect(wrapped.stat("/stat.txt")).resolves.toBeDefined();
    await expect(wrapped.unlink("/mutate.txt")).resolves.toBeUndefined();
    expect(backend.existsSync("/mutate.txt")).toBe(true);
    await expect(wrapped.access("/access.txt", fsConstants.W_OK)).resolves.toBeUndefined();
    await expect(wrapped.readlink("/readlink-link")).resolves.toBe("readlink-target.txt");
    await expect(wrapped.exists("/exists.txt")).resolves.toBe(true);
    await expect(wrapped.realpath("/realpath.txt")).resolves.toBe("/realpath.txt");
    await expect(wrapped.copyFile("/copy-src.txt", "/copy-dest.txt")).resolves.toBeUndefined();
    expect(backend.existsSync("/copy-dest.txt")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// access() bitmask decoding
// ---------------------------------------------------------------------------

describe("withGlobPolicy: access() bitmask decoding", () => {
  it("treats an omitted mode as F_OK (existence only)", async () => {
    const rules: GlobRule[] = [{ glob: "readonly.txt", mode: "deny-read", reason: "t" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/readonly.txt", "x");

    await expect(wrapped.access("/readonly.txt")).resolves.toBeUndefined();
  });

  it("denies when any requested bit in a combined mask is denied", async () => {
    const rules: GlobRule[] = [{ glob: "readonly.txt", mode: "deny-write", reason: "t" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/readonly.txt", "x");

    await expectErrno(wrapped.access("/readonly.txt", fsConstants.R_OK | fsConstants.W_OK), "EACCES");
  });
});

// ---------------------------------------------------------------------------
// truncate() gating (a backend that implements a top-level truncate — see
// src/vfs/glob-policy.ts's module comment, finding #5, for why the real
// RealFSProvider doesn't have one and this is still worth testing)
// ---------------------------------------------------------------------------

describe("withGlobPolicy: truncate", () => {
  it("gates a top-level truncate() the same as any other write-shaped operation", async () => {
    const rules: GlobRule[] = [{ glob: "frozen.txt", mode: "deny-write", reason: "frozen" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/frozen.txt", "0123456789");

    await expectErrno(wrapped.truncate("/frozen.txt", 2), "EACCES");
  });

  it("shadow-writes a truncate: appears to succeed, real content untouched", async () => {
    const rules: GlobRule[] = [{ glob: "shadowed.txt", mode: "shadow-write", reason: "t" }];
    const { backend, wrapped } = setup(rules);
    await backend.writeFile("/shadowed.txt", "0123456789");

    await expect(wrapped.truncate("/shadowed.txt", 2)).resolves.toBeUndefined();
    expect(await backend.readFile("/shadowed.txt")).toEqual(Buffer.from("0123456789"));
  });
});
