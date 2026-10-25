const fs = require("node:fs");
const delta = JSON.parse(fs.readFileSync("/opt/corb-apk-output/delta.json", "utf8"));
for (const filename of [...delta.deleted].sort((a, b) => b.length - a.length)) fs.rmSync(filename, { recursive: true, force: true });
for (const row of delta.changed.filter(row => row.type === "directory")) {
  fs.mkdirSync(row.path, { recursive: true }); fs.chownSync(row.path, row.uid, row.gid); fs.chmodSync(row.path, row.mode);
}
for (const row of delta.changed.filter(row => row.type !== "directory")) {
  if (row.type === "symlink") fs.lchownSync(row.path, row.uid, row.gid);
  else { fs.chownSync(row.path, row.uid, row.gid); fs.chmodSync(row.path, row.mode); }
}
console.log(JSON.stringify({ appliedPaths: delta.changed.length, deletedPaths: delta.deleted.length, unsafeUnconditionalReplay: true }));
