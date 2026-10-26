import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { prepareRepository, APK_PREFIX } from "../../../src/layer/prepare.ts";
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
it("keeps original signed indexes under the real APK architecture layout", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "corb-local-repository-")); dirs.push(directory); const file = path.join(directory, "index"); fs.writeFileSync(file, "original signed bytes");
  const input = prepareRepository(directory, [{ repository: "main", filename: file }]);
  expect(fs.readFileSync(path.join(input, "repositories/main/x86_64/APKINDEX.tar.gz"), "utf8")).toBe("original signed bytes");
  expect(fs.readFileSync(path.join(input, "repositories.list"), "utf8")).toBe("/corb-layer-input/repositories/main\n");
  expect(APK_PREFIX).toContain("--no-network"); expect(APK_PREFIX).not.toContain("--allow-untrusted");
});
