import fs from "node:fs";
import { runLayerPush } from "../../../src/commands/image-layer-transport.ts";

const rename = fs.renameSync;
let observed = false;
fs.renameSync = (source, destination) => {
  if (String(source).includes(".corb.sum.bind-") && String(destination).endsWith("/corb.sum")) {
    observed = true; throw Object.assign(Error("owned lockfile replacement failure"), { code: "EIO" });
  }
  return rename(source, destination);
};
try {
  let rejected = false;
  try { await runLayerPush(process.argv.slice(2)); }
  catch (error) { if (!(error instanceof Error) || !error.message.includes("owned lockfile replacement failure")) throw error; rejected = true; }
  if (!rejected || !observed) throw Error("lockfile replacement failure did not run");
  console.log("CORB_LOCKFILE_REPLACEMENT_REJECTED");
} finally { fs.renameSync = rename; }
