import { fail } from "./validate.ts";
import { assertCompatiblePackagePlan, type LayerRecipePins, type LayerPackagePin } from "./pins.ts";

export interface InstalledIdentity { P: string; V: string; A: string; C: string; D: string; p: string }
export function parseInstalledIdentities(database: string): InstalledIdentity[] {
  const names = new Set<string>();
  return database.trim().split(/\n\n+/).filter(Boolean).map((block) => {
    const result = { D: "", p: "" } as InstalledIdentity;
    const fields = new Set<string>();
    for (const line of block.split("\n")) {
      if (["P", "V", "A", "C", "D", "p"].includes(line[0]!) && line[1] === ":") {
        const key = line[0] as keyof InstalledIdentity;
        if (fields.has(key)) fail("duplicate APK identity field");
        fields.add(key);
        result[key] = line.slice(2);
      }
    }
    for (const field of ["P", "V", "A", "C"] as const) if (!result[field]) fail(`missing APK identity field ${field}`);
    if (names.has(result.P)) fail(`duplicate installed APK '${result.P}'`);
    names.add(result.P);
    return { P: result.P, V: result.V, A: result.A, C: result.C, D: result.D, p: result.p };
  });
}
/** Only complete, numbered Installing operations can authorize additions. */
export function parsePackagePlan(output: string, before: readonly InstalledIdentity[], pins: LayerRecipePins): LayerPackagePin[] {
  const additions: LayerPackagePin[] = [];
  let expectedTotal: number | undefined;
  let summary = false;
  for (const raw of output.split("\n")) {
    const line = raw.trim();
    const action = /^\((\d+)\/(\d+)\) (Installing|Upgrading|Downgrading|Reinstalling|Purging|Replacing) ([a-z0-9][a-z0-9+_.-]*) \(([^\s()]+)\)$/.exec(line);
    if (action === null) {
      if (line.startsWith("(") || /\b(?:Installing|Upgrading|Downgrading|Reinstalling|Purging|Replacing)\b/.test(line)) fail(`unrecognized APK transaction operation '${line}'`);
      if (/^OK: \d+(?:\.\d+)? (?:MiB|KiB|B) in \d+ packages$/.test(line) || /^OK: \d+ packages, \d+ dirs, \d+ files, \d+ MiB$/.test(line)) { if (summary) fail("duplicate APK plan summary"); summary = true; }
      else if (line !== "") fail(`unrecognized APK simulation output '${line}'`);
      continue;
    }
    const [, ordinal, count, operation, name, version] = action;
    expectedTotal ??= Number(count);
    if (Number(ordinal) !== additions.length + 1 || Number(count) !== expectedTotal) fail("incomplete or inconsistent APK transaction plan");
    if (operation !== "Installing" || before.some((pkg) => pkg.P === name)) fail(`incompatible base: planned ${operation} of '${name}' is forbidden`);
    const pin = pins.package.find((pkg) => pkg.name === name && pkg.version === version);
    if (pin === undefined) fail(`incompatible base: planned unbundled package '${name}=${version}'`);
    additions.push(pin);
  }
  if (!summary) fail("missing complete APK simulation summary");
  if (expectedTotal !== undefined && additions.length !== expectedTotal) fail("incomplete APK transaction plan");
  assertCompatiblePackagePlan(pins, additions.map(({ requested: _requested, ...identity }) => ({ action: "add", ...identity })));
  return additions;
}
export function assertPackageIdentities(before: readonly InstalledIdentity[], after: readonly InstalledIdentity[], additions: readonly LayerPackagePin[]): void {
  if (after.length !== before.length + additions.length) fail("composition has missing or extra package identities");
  for (const previous of before) {
    if (JSON.stringify(after.find((pkg) => pkg.P === previous.P)) !== JSON.stringify(previous)) fail(`composition changed base package '${previous.P}'`);
  }
  for (const pin of additions) {
    const actual = after.find((pkg) => pkg.P === pin.name);
    if (actual === undefined || actual.V !== pin.version || actual.C !== pin["apkindex-checksum"] || !["x86_64", "noarch"].includes(actual.A)) fail(`composition package identity mismatch '${pin.name}'`);
  }
}

/** A sanitized child APK must inherit only the frozen local repositories from its default config. */
export function validateHookRepositoryQuery(output: string, pins: LayerRecipePins, arch: string): string[] {
  const names = new Set<string>();
  for (const line of output.trim().split("\n").filter(Boolean)) {
    const match = pins.package.find((row) => line === `/corb-layer-input/repositories/${row.repository}/${arch}/${row.name}-${row.version}.apk`
      || line === `file:///corb-layer-input/repositories/${row.repository}/${arch}/${row.name}-${row.version}.apk`);
    if (match === undefined || names.has(match.name)) fail(`bare APK child escaped the frozen bundle: '${line}'`);
    names.add(match.name);
  }
  if (!pins.package.filter((row) => row.requested).every((row) => names.has(row.name))) fail("bare APK child did not resolve every exact requested input through its frozen defaults");
  return [...names].sort();
}
