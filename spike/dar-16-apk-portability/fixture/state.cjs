const fs = require("node:fs");
const crypto = require("node:crypto");
function file(filename) {
  try {
    const stat = fs.statSync(filename);
    return { uid: stat.uid, gid: stat.gid, mode: stat.mode & 0o7777,
      ...(stat.isFile() ? { sha256: crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex") } : {}) };
  } catch (error) { if (error.code === "ENOENT") return null; throw error; }
}
const accounts = fs.readFileSync("/etc/passwd", "utf8").trim().split("\n").map(line => {
  const [name, , uid, gid] = line.split(":"); return { name, uid: Number(uid), gid: Number(gid) };
});
console.log(JSON.stringify({ accounts, paths: Object.fromEntries([
  "/etc/redis.conf", "/var/lib/redis/consumer.txt", "/var/lib/apkconsumer/sentinel", "/run/redis", "/var/log/redis",
].map(filename => [filename, file(filename)])) }));
