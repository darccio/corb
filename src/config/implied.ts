// Add uncovered hosts before trust checks. Sources stay outside the effective config.
// DAR-16 can supply layer runtime hosts through extraHosts after its schema is final.
import { findBrokeredProvider, uncoveredHosts } from "../auth/provider.ts";
import type { EffectiveConfig } from "./load.ts";
import type { ConfigLayer } from "./schema.ts";

export type ImpliedHostSource =
  | { kind: "agent-provider"; provider: string; layer: "global" }
  | { kind: "agent-provider"; provider: string; layer: "workspace"; workspace: string };

export interface ImpliedHost {
  host: string;
  source: ImpliedHostSource;
}

export function describeImpliedHostSource(source: ImpliedHostSource): string {
  const setting = `[agent] provider = "${source.provider}"`;
  return source.layer === "workspace" ? `${setting} in workspace "${source.workspace}"` : setting;
}

export function agentProviderLayer(_globalLayer: ConfigLayer, workspace?: { name: string; layer: ConfigLayer }):
  { layer: "global" } | { layer: "workspace"; workspace: string } {
  return workspace?.layer.agent?.provider !== undefined
    ? { layer: "workspace", workspace: workspace.name } : { layer: "global" };
}

export function applyImpliedHosts(config: EffectiveConfig, opts: {
  providerLayer?: { layer: "global" } | { layer: "workspace"; workspace: string };
  extraHosts?: readonly ImpliedHost[];
} = {}): { config: EffectiveConfig; implied: ImpliedHost[] } {
  const provider = findBrokeredProvider(config.agent?.provider);
  const candidates: ImpliedHost[] = provider === undefined ? [] : provider.apiHosts.map((host) => ({
    host,
    source: { kind: "agent-provider", provider: provider.id, ...(opts.providerLayer ?? { layer: "global" }) },
  }));
  candidates.push(...(opts.extraHosts ?? []));
  const allow = [...(config.egress.allow ?? [])];
  const implied: ImpliedHost[] = [];
  for (const candidate of candidates) {
    if (uncoveredHosts([candidate.host], allow).length > 0) {
      allow.push(candidate.host);
      implied.push(candidate);
    }
  }
  return {
    config: { ...config, egress: { ...config.egress, allow } },
    implied,
  };
}
