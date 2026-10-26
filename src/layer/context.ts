import fs from "node:fs";
import { loadWorkspaceContext } from "../config/resolve.ts";
import { mergeConfigLayers } from "../config/load.ts";
import { selectWorkspace } from "../config/workspaces.ts";
import { corbConfigDir } from "../config/paths.ts";
import { assertLayerTarget, hashLayerDefinition } from "./definition.ts";
import { readLayerLock, serializeLayerLock } from "./pins.ts";
import { nativeLayerArch, fail, sha256 } from "./validate.ts";

export function selectLayerWorkspace(name?: string, configDir = corbConfigDir(), cwd = process.cwd()) {
  const context = loadWorkspaceContext(configDir);
  const selected = selectWorkspace({ listing: context.listing, loadLayer: context.loadLayer,
    ...(name === undefined ? { dir: cwd } : { byName: name }) });
  if (selected === undefined) fail("no matching workspace. Use --workspace NAME");
  const config = mergeConfigLayers([context.configTomlLayer, selected.layer]);
  if (config.image === undefined) fail(`workspace '${selected.name}' requires an image.layer definition`);
  const arch = nativeLayerArch();
  assertLayerTarget(config.image.layer, arch);
  const pins = readLayerLock(selected.entry.dir);
  const snapshot = JSON.stringify({ source: selected.entry.corbToml, directory: selected.entry.realPath,
    text: sha256(fs.readFileSync(selected.entry.corbToml)), global: context.configTomlLayer,
    definition: hashLayerDefinition(config.image.layer), pins: pins === undefined ? null : serializeLayerLock(pins) });
  return { selected, config, definition: config.image.layer, arch, pins: pins?.target[arch], snapshot,
    recheck: () => {
      const next = selectLayerWorkspace(name, configDir, cwd);
      if (next.snapshot !== snapshot) fail("selected workspace source, definition or pins changed during operation");
    } };
}
export type LayerContext = ReturnType<typeof selectLayerWorkspace>;
