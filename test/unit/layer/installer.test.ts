import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { assertInstallerAbsent } from "../../../image/helpers/layer.mjs";
import { sha256 } from "../../../src/layer/validate.ts";
const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
it("rejects authenticated installer bytes under an arbitrary copied filename", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-installer-absence-")); directories.push(root);
  const directory = path.join(root, "usr/local/bin"); fs.mkdirSync(directory, { recursive: true });
  const bytes = Buffer.from("known authenticated installer"); const identity = { sha256: sha256(bytes), size: bytes.length };
  expect(() => assertInstallerAbsent(identity, root)).not.toThrow();
  fs.writeFileSync(path.join(directory, "copied-installer"), bytes);
  expect(() => assertInstallerAbsent(identity, root)).toThrow("installer was copied into the checkpoint");
  fs.writeFileSync(path.join(directory, "copied-installer"), Buffer.alloc(bytes.length));
  expect(() => assertInstallerAbsent(identity, root)).not.toThrow();
});
