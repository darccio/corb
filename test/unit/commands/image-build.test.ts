import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  build: vi.fn(), importImage: vi.fn(), tag: vi.fn(), verify: vi.fn(),
}));
vi.mock("@earendil-works/gondolin", async (load) => ({
  ...await load<object>(),
  buildAssets: mocks.build,
  importImageFromDirectory: mocks.importImage,
  tagImage: mocks.tag,
}));
vi.mock("../../../image/verify.ts", () => ({ verifyImage: mocks.verify }));
import { imageBuild, runImageCommand } from "../../../src/commands/image.ts";
const dirs: string[] = [];
beforeEach(() => {
  vi.clearAllMocks();
  mocks.build.mockResolvedValue({ outputDir: "/candidate" });
  mocks.importImage.mockReturnValue({ buildId: "candidate-id" });
  mocks.tag.mockImplementation((_id, reference) => ({ reference, targets: { x86_64: "candidate-id" } }));
  mocks.verify.mockResolvedValue({ ok: true, gates: [{ name: "user", ok: true, detail: "pass" }] });
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});
function args() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-image-build-"));
  dirs.push(dir);
  const filename = path.join(dir, "config.json");
  fs.writeFileSync(filename, JSON.stringify({ arch: "x86_64", distro: "alpine" }));
  vi.stubEnv("CORB_CACHE_DIR", dir);
  return ["--config", filename, "--arch", "x86_64"];
}
describe("image publication", () => {
  it("writes content and version tags by default", async () => {
    const report = await imageBuild(args());
    expect(mocks.tag.mock.calls.map((call) => call[1])).toEqual([
      expect.stringMatching(/^corb:0\.1\.0-x86_64-[a-f0-9]{8}$/), "corb:0.1.0",
    ]);
    expect(report.aliasTag?.reference).toBe("corb:0.1.0");
  });
  for (const ref of ["corb-spike:dar-20-test", "corb:0.1.0"]) {
    it(`writes only explicitly requested ${ref}`, async () => {
      const report = await imageBuild([...args(), "--tag", ref]);
      expect(mocks.tag.mock.calls.map((call) => call[1])).toEqual([ref]);
      expect(report.primaryTag.reference).toBe(ref);
      expect(report.aliasTag).toBeUndefined();
    });
  }
  it("reports only the tag written", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await runImageCommand(["build", ...args(), "--tag", "corb-spike:dar-20-output"]);
    expect(log.mock.calls.filter(([line]) => String(line).includes("tagged"))).toHaveLength(1);
  });
  it("imports nothing and writes no refs after a failed gate", async () => {
    mocks.verify.mockResolvedValue({ ok: false, gates: [{ name: "ca-trust", ok: false, detail: "TLS failure" }] });
    await expect(imageBuild(args())).rejects.toThrow(/verification failed/);
    expect(mocks.importImage).not.toHaveBeenCalled();
    expect(mocks.tag).not.toHaveBeenCalled();
  });
  it("rejects missing init bytes before starting a build", async () => {
    const argv = args();
    fs.writeFileSync(argv[1]!, JSON.stringify({ arch: "x86_64", distro: "alpine", init: { rootfsInitExtra: "absent" } }));
    await expect(imageBuild(argv)).rejects.toThrow(/ENOENT/);
    expect(mocks.build).not.toHaveBeenCalled();
    expect(mocks.tag).not.toHaveBeenCalled();
  });
});
