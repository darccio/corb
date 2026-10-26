import fs from "node:fs";
import { VM, VmCheckpoint } from "@earendil-works/gondolin";
import { cleanVmOptions, observeOptionsCall } from "../helpers/vm-options.ts";

const markerFile = process.env.CORB_E2E_VM_MARKERS; const receipt = process.env.CORB_E2E_VM_RECEIPT;
if (!markerFile || !receipt || fs.statSync(markerFile).size > 64 * 1024) throw Error("private VM options observation requires bounded marker and receipt files");
const markers = JSON.parse(fs.readFileSync(markerFile, "utf8")) as string[];
const rows: Array<{ kind: "create" | "resume"; count: number; clean: boolean }> = [];
fs.writeFileSync(receipt, "[]", { flag: "wx", mode: 0o600 });
function observe(kind: "create" | "resume", options: unknown) {
  let clean = false;
  try { clean = cleanVmOptions(options, markers); }
  finally { rows.push({ kind, count: rows.filter((row) => row.kind === kind).length + 1, clean }); fs.writeFileSync(receipt!, JSON.stringify(rows), { mode: 0o600 }); }
  if (!clean) throw Error("registry credential marker entered VM options");
}
VM.create = observeOptionsCall(VM.create, (options) => observe("create", options));
VmCheckpoint.prototype.resume = observeOptionsCall(VmCheckpoint.prototype.resume, (options) => observe("resume", options));
