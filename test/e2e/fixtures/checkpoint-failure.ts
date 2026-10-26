import fs from "node:fs";
import { runLayerBuild } from "../../../src/commands/image-layer.ts";
const rename = fs.renameSync;
let source: string | undefined; let destination: string | undefined;
fs.renameSync = (from, to) => {
  if (String(from).endsWith("/builder.qcow2") && String(to).endsWith("/checkpoint.qcow2")) {
    source = String(from); destination = String(to); fs.writeFileSync(to, "owned partial checkpoint");
    throw Object.assign(Error("induced checkpoint move failure"), { code: "EIO" });
  }
  return rename(from, to);
};
try {
  let rejected = false;
  try { await runLayerBuild(["--workspace", "package"]); }
  catch (error) { if (!(error instanceof Error) || !error.message.includes("induced checkpoint move failure")) throw error; rejected = true; }
  if (!rejected || source === undefined || destination === undefined) throw Error("SDK checkpoint move fault was not exercised");
  if (fs.existsSync(source) || fs.existsSync(destination)) throw Error("owned checkpoint source or partial destination survived");
  console.log(`CORB_CHECKPOINT_FAILURE=${JSON.stringify({ source, destination, sourceExists: false, destinationExists: false })}`);
} finally { fs.renameSync = rename; }
