import { findBrokeredProvider, unreachableApiHosts } from "../auth/provider.ts";
import type { EffectiveConfig } from "./load.ts";

export interface ImpliedHostSource {
  kind: "agent-provider";
  provider: string;
  layer: "global";
}

export interface ImpliedHost {
  host: string;
  source: ImpliedHostSource;
}

export function describeImpliedHostSource(source: ImpliedHostSource): string {
  return `[agent] provider = "${source.provider}"`;
}

// DAR-17 extends this entry point for workspace providers and layer run-time hosts.
export function applyImpliedHosts(config: EffectiveConfig): { config: EffectiveConfig; implied: ImpliedHost[] } {
  const provider = findBrokeredProvider(config.agent?.provider);
  const hosts = provider === undefined ? [] : unreachableApiHosts(provider, config.egress.allow);
  const implied: ImpliedHost[] = provider === undefined ? [] : hosts.map((host) => ({
    host,
    source: { kind: "agent-provider", provider: provider.id, layer: "global" },
  }));
  return {
    config: { ...config, egress: { ...config.egress, allow: [...(config.egress.allow ?? []), ...hosts] } },
    implied,
  };
}
