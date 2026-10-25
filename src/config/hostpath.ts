import path from "node:path";
import { expandHomePrefix } from "./paths.ts";
import { ConfigParseError, type ConfigLayer } from "./schema.ts";

export interface ResolveLayerHostsOptions {
  home: string;
  projectsRoot?: string;
  sourceLabel: string;
}

/** Expand persistent host paths before selection, trust, and mount checks. */
export function resolveLayerHosts(layer: ConfigLayer, { home, projectsRoot, sourceLabel }: ResolveLayerHostsOptions): ConfigLayer {
  if (layer.dir === undefined) {
    return { ...layer };
  }
  return {
    ...layer,
    dir: layer.dir.map((entry, index) => {
      if (entry.host === undefined) {
        return { ...entry };
      }
      const location = `dir[${index}].host`;
      const raw = entry.host;
      if (raw === "" || (raw.startsWith("~") && raw !== "~" && !raw.startsWith("~/")) ||
          (raw.startsWith("$") && raw !== "$HOME" && !raw.startsWith("$HOME/"))) {
        throw new ConfigParseError(sourceLabel, `field '${location}' must be non-empty and may only use ~ or $HOME as a complete leading path component`, location);
      }
      const expanded = expandHomePrefix(raw, home);
      if (path.isAbsolute(expanded)) {
        return { ...entry, host: expanded };
      }
      if (projectsRoot === undefined) {
        throw new ConfigParseError(sourceLabel, `field '${location}' needs [workspaces] projects-root for a relative host. Relative hosts are not resolved against the current directory`, location);
      }
      return { ...entry, host: path.resolve(projectsRoot, expanded) };
    }),
  };
}
