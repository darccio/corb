import { loadWorkspaceContext, realpathOrResolve, resolveWorkspace, type ResolvedWorkspace } from "./resolve.ts";
import { evaluateTrust, hashEffectiveConfig, type TrustEvaluation, type TrustStore, type TrustedWorkspaceRecord } from "./trust.ts";
import { parseWorkspaceTrustKey, selectWorkspace, workspaceTrustKey, type ListedWorkspace, type WorkspaceListing } from "./workspaces.ts";
import type { EffectiveConfig } from "./load.ts";

export type WorkspaceTrustStatus = "none" | "trusted" | "narrowed" | "changed" | "error";

export interface InspectedTrustRecord {
  key: string;
  dir: string;
  kind: "host" | "extra-mount";
  status: WorkspaceTrustStatus;
  record?: TrustedWorkspaceRecord;
  evaluation?: TrustEvaluation;
  hashMatches?: boolean;
  error?: string;
}

export interface WorkspaceTrustInspection {
  name: string;
  entry?: ListedWorkspace;
  dirs: Array<{ name: string; host: string }>;
  resolved?: ResolvedWorkspace;
  error?: string;
  records: InspectedTrustRecord[];
  status: WorkspaceTrustStatus;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function workspaceTrustStatus(records: readonly InspectedTrustRecord[], error?: string): WorkspaceTrustStatus {
  if (error !== undefined) return "error";
  for (const status of ["error", "changed", "narrowed", "trusted"] as const) {
    if (records.some((record) => record.status === status)) return status;
  }
  return "none";
}

function compareRecord(item: InspectedTrustRecord, config: EffectiveConfig): void {
  item.evaluation = evaluateTrust(item.record?.acceptedConfig, config);
  if (item.record === undefined) {
    item.status = "none";
    return;
  }
  item.hashMatches = hashEffectiveConfig(config) === item.record.configHash;
  item.status = item.evaluation.verdict === "requires-confirmation" ? "changed"
    : item.evaluation.narrowed.length > 0 ? "narrowed" : "trusted";
}

/** Compare personal records without accepting changes or deleting stale entries. */
export function inspectWorkspaceTrust(name: string, { configDir, store }: { configDir: string; store: TrustStore }): WorkspaceTrustInspection {
  const context = loadWorkspaceContext(configDir);
  const entry = context.listing.workspaces.find((candidate) => candidate.name === name);
  const result: WorkspaceTrustInspection = { name, dirs: [], records: [], status: "none", ...(entry === undefined ? {} : { entry }) };
  try {
    const selected = selectWorkspace({ listing: context.listing, byName: name, loadLayer: context.loadLayer })!;
    result.dirs = (selected.layer.dir ?? []).filter((dir) => dir.host !== undefined)
      .map((dir) => ({ name: dir.name!, host: realpathOrResolve(dir.host!) }));
    result.resolved = resolveWorkspace(undefined, {}, { configDir, workspace: name });
  } catch (error) {
    result.error = message(error);
  }
  const keys = new Set<string>();
  for (const dir of result.dirs) {
    const key = workspaceTrustKey(name, dir.host);
    if (keys.has(key)) continue;
    keys.add(key);
    const record = store[key];
    const item: InspectedTrustRecord = { key, dir: dir.host, kind: "host", status: "none", ...(record === undefined ? {} : { record }) };
    if (result.resolved === undefined) {
      item.error = result.error!;
      item.status = "error";
    } else {
      compareRecord(item, result.resolved.persistentConfig);
    }
    result.records.push(item);
  }
  for (const [key, record] of Object.entries(store)) {
    const parsed = parseWorkspaceTrustKey(key);
    if (parsed?.name !== name || keys.has(key)) continue;
    const item: InspectedTrustRecord = { key, dir: parsed.dir, kind: "extra-mount", record, status: "none" };
    try {
      compareRecord(item, resolveWorkspace(parsed.dir, {}, { configDir, workspace: name }).persistentConfig);
    } catch (error) {
      item.error = message(error);
      item.status = "error";
    }
    result.records.push(item);
  }
  result.status = workspaceTrustStatus(result.records, result.error);
  return result;
}

export function orphanTrustRecords(store: TrustStore, listing: WorkspaceListing): Array<{ key: string; name: string; dir: string; record: TrustedWorkspaceRecord }> {
  const names = new Set(listing.workspaces.filter((entry) => entry.valid).map((entry) => entry.name));
  return Object.entries(store).flatMap(([key, record]) => {
    const parsed = parseWorkspaceTrustKey(key);
    return parsed === undefined || names.has(parsed.name) ? [] : [{ key, ...parsed, record }];
  });
}
