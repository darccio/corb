import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { runImageLs } from "../../../src/commands/image-local.ts";
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
it("lists local refs read-only and states its untagged-object limit in JSON", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-image-list-")); dirs.push(dir); vi.stubEnv("GONDOLIN_IMAGE_STORE", path.join(dir, "store")); vi.stubEnv("CORB_STATE_DIR", path.join(dir, "state"));
  const log = vi.spyOn(console, "log").mockImplementation(() => {}); runImageLs(["--json"]);
  expect(JSON.parse(log.mock.calls[0]![0])).toMatchObject({ version: 1, inventory: "local-sdk-refs", includesUntaggedObjects: false, refs: [], compositions: [] });
  expect(fs.readdirSync(dir)).toEqual([]);
  expect(() => runImageLs(["extra"])).toThrow(); expect(() => runImageLs(["--unknown"])).toThrow();
});
