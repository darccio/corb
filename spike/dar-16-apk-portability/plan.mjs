export function parsePlan(stdout, before) {
  const rows = [];
  for (const line of stdout.split("\n")) {
    const match = /^\(\d+\/\d+\)\s+(Installing|Upgrading|Downgrading|Reinstalling|Purging)\s+(\S+)\s+\(([^)]+)\)/.exec(line.trim());
    if (match) rows.push({ operation: match[1], name: match[2], version: match[3] });
    else if (/^\(\d+\/\d+\)/.test(line.trim())) throw new Error("unrecognized APK transaction line: " + line);
  }
  const existing = new Set(before.map(row => row.P));
  for (const row of rows) {
    if (row.operation !== "Installing" || existing.has(row.name)) throw new Error("planned base package change: " + JSON.stringify(row));
  }
  return rows.map(({ name, version }) => ({ name, version }));
}

export function delta(before, after) {
  const previous = new Map(before.map(row => [row.path, row]));
  const current = new Map(after.map(row => [row.path, row]));
  const changed = after.filter(row => JSON.stringify(previous.get(row.path)) !== JSON.stringify(row));
  const deleted = before.filter(row => !current.has(row.path)).map(row => row.path);
  return { changed, deleted, preimages: [...changed.map(row => ({ path: row.path, before: previous.get(row.path) ?? null })),
    ...deleted.map(filename => ({ path: filename, before: previous.get(filename) }))] };
}

export function assertPreimages(preimages, destination) {
  const actual = new Map(destination.map(row => [row.path, row]));
  const mismatches = preimages.filter(row => JSON.stringify(row.before) !== JSON.stringify(actual.get(row.path) ?? null)).map(row => row.path);
  if (mismatches.length) throw new Error("filesystem delta preconditions differ: " + mismatches.join(", "));
}
