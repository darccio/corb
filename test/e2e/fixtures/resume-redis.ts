import fs from "node:fs";
import path from "node:path";
import { selectLayerWorkspace } from "../../../src/layer/context.ts";
import { preflightComposition } from "../../../src/layer/generation.ts";
import { layerGuest, withLayerVm, verifyProductionVm, VERIFIER_HOSTS } from "../../../src/layer/vm.ts";
import { hashFile } from "../../../src/layer/state.ts";

const workspace = process.argv[2]!; const expectation = process.argv[3]!;
const composition = await preflightComposition(selectLayerWorkspace(workspace));
await composition.recheck();
const before = await hashFile(composition.checkpoint);
const result = await withLayerVm(composition.base, "corb-redis-explicit-acceptance", VERIFIER_HOSTS, async (vm) => {
  await layerGuest(vm, "runtime", { plan: composition.metadata.runtime, expected: composition.metadata.mapping });
  const source = fs.readFileSync(path.join(process.cwd(), "test/e2e/fixtures/redis-default.mjs"), "utf8");
  const check = await vm.exec(["/usr/bin/node", "--input-type=module", "-e", source, expectation], { stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(45_000) });
  process.stdout.write(check.stdout + check.stderr);
  if (!check.ok) throw Error(`explicit packaged-default service check failed (${check.exitCode})`);
  const evidence = JSON.parse(fs.readFileSync(path.join(composition.directory, "evidence.json"), "utf8"));
  await layerGuest(vm, "verify", evidence);
  const verification = await verifyProductionVm(vm);
  return { generation: composition.metadata.generation, base: composition.base.manifest.buildId, checkpointSha256: before, verification };
}, { checkpoint: composition.load(), verifier: true });
if (await hashFile(composition.checkpoint) !== before) throw Error("Redis resume changed the immutable checkpoint");
console.log(`CORB_REDIS_RESUME=${JSON.stringify(result)}`);
