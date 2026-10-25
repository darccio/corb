const fs = require("node:fs");
const crypto = require("node:crypto");
const rootDevice = fs.statSync("/").dev;
const rows = [];
function walk(filename) {
  const stat = fs.lstatSync(filename);
  if (stat.dev !== rootDevice) return;
  const row = { path: filename, mode: stat.mode & 0o7777, uid: stat.uid, gid: stat.gid };
  if (stat.isDirectory()) row.type = "directory";
  else if (stat.isFile()) {
    row.type = "file";
    row.size = stat.size;
    row.sha256 = crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
  } else if (stat.isSymbolicLink()) {
    row.type = "symlink";
    row.target = fs.readlinkSync(filename);
  } else row.type = "special";
  rows.push(row);
  if (stat.isDirectory()) for (const name of fs.readdirSync(filename).sort()) walk(filename === "/" ? "/" + name : filename + "/" + name);
}
walk("/");
process.stdout.write(JSON.stringify(rows));
