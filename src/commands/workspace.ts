import { parseArgs } from "node:util";
import { corbConfigDir } from "../config/paths.ts";
import { inspectWorkspaceTrust, orphanTrustRecords, type WorkspaceTrustInspection, type WorkspaceTrustStatus } from "../config/inspect.ts";
import { loadWorkspaceContext, readTrustStore } from "../config/resolve.ts";
import { assertValidWorkspaceName, type ListedWorkspace, type WorkspaceSource } from "../config/workspaces.ts";
import { renderConfigSections, renderTrust, renderTrustedSnapshot } from "../config/render.ts";
import type { EffectiveConfig } from "../config/load.ts";
import type { ImpliedHost } from "../config/implied.ts";
import type { TrustEvaluation, TrustedWorkspaceRecord } from "../config/trust.ts";

export interface WorkspaceLsArgs { json: boolean }
export interface WorkspaceShowArgs extends WorkspaceLsArgs { name: string }

export function parseWorkspaceLsArgs(argv: string[]): WorkspaceLsArgs {
  const { values, positionals } = parseArgs({ args: argv, options: { json: { type: "boolean" } }, strict: true, allowPositionals: true });
  if (positionals.length > 0) throw new Error(`corb workspace ls: unexpected argument '${positionals[0]}'`);
  return { json: values.json ?? false };
}

export function parseWorkspaceShowArgs(argv: string[]): WorkspaceShowArgs {
  const { values, positionals } = parseArgs({ args: argv, options: { json: { type: "boolean" } }, strict: true, allowPositionals: true });
  if (positionals.length !== 1) throw new Error("corb workspace show: expected exactly one workspace name");
  const name = positionals[0]!;
  assertValidWorkspaceName(name);
  return { name, json: values.json ?? false };
}

interface SourceInfo { index: number; raw: string; path: string }
type Replaced = ListedWorkspace["replaced"];

export interface WorkspaceLsJson {
  workspaces: Array<{
    name: string;
    source: SourceInfo;
    dir: string;
    valid: boolean;
    reason: string | null;
    replaced: Replaced;
    dirs: WorkspaceTrustInspection["dirs"];
    trust: WorkspaceTrustStatus;
    records: number;
    error: string | null;
  }>;
  orphanRecords: Array<{ key: string; name: string; dir: string }>;
}

export interface WorkspaceShowJson {
  name: string;
  source: SourceInfo;
  dir: string;
  replaced: Replaced;
  primary: string | null;
  error: string | null;
  config: EffectiveConfig | null;
  impliedHosts: ImpliedHost[];
  records: Array<{
    key: string;
    dir: string;
    kind: "host" | "extra-mount";
    status: WorkspaceTrustStatus;
    acceptedAt: number | null;
    configHash: string | null;
    hashMatches: boolean | null;
    acceptedConfig: EffectiveConfig | null;
    trust: TrustEvaluation | null;
    error: string | null;
  }>;
}

function sourceInfo(entry: ListedWorkspace, sources: readonly WorkspaceSource[]): SourceInfo {
  const source = sources[entry.source]!;
  return { index: entry.source, raw: source.raw, path: source.path };
}

export function loadWorkspaceLs(configDir: string = corbConfigDir()): { payload: WorkspaceLsJson; sources: WorkspaceSource[] } {
  const { listing } = loadWorkspaceContext(configDir);
  const store = readTrustStore(configDir);
  const workspaces = listing.workspaces.map((entry) => {
    const inspection = inspectWorkspaceTrust(entry.name, { configDir, store });
    return {
      name: entry.name, source: sourceInfo(entry, listing.sources), dir: entry.dir,
      valid: entry.valid, reason: entry.reason ?? null, replaced: entry.replaced,
      dirs: inspection.dirs, trust: inspection.status, records: inspection.records.length, error: inspection.error ?? null,
    };
  });
  const orphanRecords = orphanTrustRecords(store, listing).map(({ key, name, dir }) => ({ key, name, dir }));
  return { payload: { workspaces, orphanRecords }, sources: listing.sources };
}

export function loadWorkspaceShow(name: string, configDir: string = corbConfigDir()): WorkspaceShowJson {
  const { listing } = loadWorkspaceContext(configDir);
  const inspection = inspectWorkspaceTrust(name, { configDir, store: readTrustStore(configDir) });
  if (inspection.entry === undefined) throw new Error(inspection.error ?? `unknown workspace '${name}'`);
  const { entry, resolved } = inspection;
  return {
    name, source: sourceInfo(entry, listing.sources), dir: entry.dir, replaced: entry.replaced,
    primary: resolved?.primary ?? null, error: inspection.error ?? null, config: resolved?.fullConfig ?? null,
    impliedHosts: resolved?.impliedHosts ?? [],
    records: inspection.records.map((item) => ({
      key: item.key, dir: item.dir, kind: item.kind, status: item.status,
      acceptedAt: item.record?.acceptedAt ?? null, configHash: item.record?.configHash ?? null,
      hashMatches: item.hashMatches ?? null, acceptedConfig: item.record?.acceptedConfig ?? null,
      trust: item.evaluation ?? null, error: item.error ?? null,
    })),
  };
}

export function renderWorkspaceLsText(payload: WorkspaceLsJson, sources: readonly WorkspaceSource[] = []): string {
  const lines: string[] = [];
  if (payload.workspaces.length === 0) {
    lines.push("corb workspace ls: no workspaces.");
    for (const source of sources) lines.push(`source: ${source.raw} (resolved ${source.path}${source.exists ? "" : "; missing"})`);
    if (sources.length === 0) lines.push("sources: (none)");
  } else {
    const rows = [["NAME", "SOURCE", "DIRS", "TRUST"], ...payload.workspaces.map((entry) => [
      entry.name, entry.source.raw, entry.dirs.map((dir) => `${dir.name}=${dir.host}`).join(", ") || "-",
      `${entry.trust}${entry.records >= 2 ? ` (${entry.records} records)` : ""}`,
    ])];
    const widths = rows[0]!.map((_, index) => Math.max(...rows.map((row) => row[index]!.length)));
    for (const row of rows) lines.push(row.map((value, index) => index === row.length - 1 ? value : value.padEnd(widths[index]!)).join("  "));
    for (const entry of payload.workspaces) {
      if (!entry.valid) lines.push(`  ${entry.name}: invalid: ${entry.reason}`);
      else if (entry.error !== null) lines.push(`  ${entry.name}: cannot compare: ${entry.error}`);
      for (const replaced of entry.replaced) lines.push(`  ${entry.name}: replaces ${replaced.dir}`);
    }
  }
  if (payload.orphanRecords.length > 0) {
    lines.push("", "trust records for workspaces that no longer exist:");
    for (const record of payload.orphanRecords) lines.push(`  ${record.key}`);
  }
  lines.push("This command only reads workspace definitions and trust records.");
  return lines.join("\n");
}

export function renderWorkspaceLsJson(payload: WorkspaceLsJson): string {
  return JSON.stringify(payload, null, 2);
}

export function renderWorkspaceShowText(payload: WorkspaceShowJson): string {
  const lines = [
    `workspace: ${payload.name}`,
    `source: ${payload.source.index} (raw ${payload.source.raw}; resolved ${payload.source.path})`,
    `directory: ${payload.dir}`,
    ...payload.replaced.map((entry) => `replaces: ${entry.dir} (source ${entry.source})`),
    `primary: ${payload.primary ?? "(none)"}`,
  ];
  if (payload.error !== null) {
    lines.push(`cannot compare: ${payload.error}`);
    if (payload.error.includes("no hosted directory of its own")) lines.push(`Run with --workspace ${payload.name} DIR.`);
  }
  if (payload.config !== null) lines.push("", "effective config:", ...renderConfigSections(payload.config, payload.impliedHosts).map((line) => `  ${line}`));
  lines.push("", `trust records (${payload.records.length}):`);
  for (const item of payload.records) {
    lines.push(`key: ${item.key}`, `  kind: ${item.kind}`, `  status: ${item.status}`);
    if (item.error !== null) lines.push(`  cannot compare: ${item.error}`);
    if (item.trust !== null) {
      lines.push(...renderTrust(item.trust, item.key, { selectedWorkspace: { name: payload.name }, dir: item.dir, positionalDirAdded: item.kind === "extra-mount" }, item.hashMatches ?? undefined));
    }
    if (item.acceptedConfig === null) lines.push("  (no record; the first run needs --trust-config)");
    const record: TrustedWorkspaceRecord | undefined = item.acceptedConfig === null ? undefined : {
      acceptedAt: item.acceptedAt!, configHash: item.configHash!, acceptedConfig: item.acceptedConfig,
    };
    lines.push(...renderTrustedSnapshot(record, item.hashMatches ?? undefined));
  }
  return lines.join("\n");
}

export function renderWorkspaceShowJson(payload: WorkspaceShowJson): string {
  return JSON.stringify(payload, null, 2);
}

export async function runWorkspaceLsCommand(argv: string[]): Promise<void> {
  const args = parseWorkspaceLsArgs(argv);
  const { payload, sources } = loadWorkspaceLs();
  console.log(args.json ? renderWorkspaceLsJson(payload) : renderWorkspaceLsText(payload, sources));
}

export async function runWorkspaceShowCommand(argv: string[]): Promise<void> {
  const args = parseWorkspaceShowArgs(argv);
  const payload = loadWorkspaceShow(args.name);
  console.log(args.json ? renderWorkspaceShowJson(payload) : renderWorkspaceShowText(payload));
}

export async function runWorkspaceCommand(argv: string[]): Promise<void> {
  const [sub, ...rest] = argv;
  if (sub === "ls") return runWorkspaceLsCommand(rest);
  if (sub === "show") return runWorkspaceShowCommand(rest);
  throw new Error(`corb workspace: unsupported subcommand '${sub}' (use 'ls' or 'show')`);
}
