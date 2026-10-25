import { root, runtime, evidence, fixed, sdk, prepare, read, save, state, usingVm, execute, database, closeAndCheck, sourceIdentity } from "./common.mjs";
import { parsePlan } from "./plan.mjs";
import path from "node:path";
import fs from "node:fs";

prepare("verify");
const prepared = read("prepared");
const targets = prepared.targets.map(row => row.P + "=" + row.V).join(" ");
try {
  const result = await usingVm(fixed, "resolve", { install: true }, undefined, async vm => {
    const before = await database(vm, "resolve-db");
    await execute(vm, "installer-version", "/opt/corb-apk-input/bin/apk.static --version");
    const positive = await execute(vm, "resolve-positive", "/opt/corb-apk-input/bin/apk.static --no-cache add --simulate " + targets);
    const additions = parsePlan(positive.stdout, before.records);
    const negative = await execute(vm, "resolve-base-upgrade", "/opt/corb-apk-input/bin/apk.static --no-cache add --simulate libssl3=" + prepared.negativeTargets.find(row => row.P === "libssl3").V);
    let rejected;
    try { parsePlan(negative.stdout, before.records); }
    catch (error) { rejected = String(error); }
    if (!rejected) throw new Error("base upgrade negative was not rejected");
    const sudo = await execute(vm, "resolve-sudo", "/opt/corb-apk-input/bin/apk.static --no-cache add --simulate sudo=" + prepared.negativeTargets.find(row => row.P === "sudo").V);
    const sudoAdditions = parsePlan(sudo.stdout, before.records);
    return { before: { sha256: before.sha256, records: before.records }, positive: additions, sudo: sudoAdditions,
      upgradeRejected: rejected, sourceIdentity };
  });
  state("resolution", result);
  save("resolution", result);
  const plan = path.join(runtime, "needed-packages.json");
  fs.writeFileSync(plan, JSON.stringify([...result.positive, ...result.sudo]));
  prepare("packages", plan);
  prepare("negative");
  console.log(JSON.stringify({ resolved: result.positive, rejected: result.upgradeRejected, evidence }));
} finally { await closeAndCheck(); }
