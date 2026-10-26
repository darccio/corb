import path from "node:path";
import { containsPosix, normalizedPosixPath, type LayerPayload } from "./definition.ts";
import { fail, integer } from "./validate.ts";

export const SDK_EXPANDED_LIMIT = 2 * 1024 ** 3;
export const SDK_ENTRY_LIMIT = 100000;
export const SDK_PATH_LIMIT = 4096;
export interface SdkArchiveEntry {
  path: string;
  type: string;
  size: number;
  mode: number;
  pax?: Readonly<Record<string, string>>;
}
export interface ValidatedSdkEntry { path: string; type: "file" | "directory"; size: number; mode: number }

/** Validate effective tar headers after archive authentication. This function performs no extraction. */
export function validateSdkArchiveEntries(entries: readonly SdkArchiveEntry[], payload: LayerPayload): ValidatedSdkEntry[] {
  if (entries.length > SDK_ENTRY_LIMIT) fail("SDK archive exceeds 100000 entries");
  let total = 0;
  const seen = new Set<string>();
  const files = new Set<string>();
  const results: ValidatedSdkEntry[] = [];
  for (const entry of entries) {
    if (entry.type !== "file" && entry.type !== "directory") fail(`SDK archive forbids entry type '${entry.type}'`);
    integer(entry.mode, "SDK archive mode", 0, 0o777);
    integer(entry.size, "SDK archive size", 0, SDK_EXPANDED_LIMIT);
    if (entry.type === "directory" && entry.size !== 0) fail("SDK directory has file data");
    for (const key of Object.keys(entry.pax ?? {})) {
      if (!["path", "size", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"].includes(key)) fail(`SDK archive forbids extended metadata '${key}'`);
    }
    if (entry.pax?.size !== undefined && entry.pax.size !== String(entry.size)) fail("SDK effective size disagrees with extended header");
    const effective = entry.pax?.path ?? entry.path;
    const raw = entry.type === "directory" && effective.endsWith("/") ? effective.slice(0, -1) : effective;
    normalizedPosixPath(raw, "SDK archive path", false);
    const stripped = raw.split("/").slice(payload["strip-components"]).join("/");
    total += entry.size;
    if (total > SDK_EXPANDED_LIMIT) fail("SDK archive exceeds 2 GiB expanded bytes");
    if (seen.has(stripped)) fail(`duplicate SDK archive path '${stripped}'`);
    seen.add(stripped);
    if (stripped === "") {
      if (entry.type !== "directory") fail("strip-components removes a complete SDK file path");
      continue;
    }
    if (Buffer.byteLength(stripped, "utf8") > SDK_PATH_LIMIT) fail("SDK path exceeds 4096 UTF-8 bytes");
    const destination = path.posix.join(payload.destination, stripped);
    if (!containsPosix(payload.destination, destination)) fail("SDK archive escapes payload destination");
    if (entry.type === "file") files.add(stripped);
    results.push({ path: stripped, type: entry.type, size: entry.size, mode: entry.type === "directory" ? 0o555 : 0o444 | (entry.mode & 0o111) });
  }
  for (const entry of results) {
    let parent = path.posix.dirname(entry.path);
    while (parent !== ".") {
      if (files.has(parent)) fail("SDK file is an ancestor of another archive entry");
      parent = path.posix.dirname(parent);
    }
  }
  return results;
}
