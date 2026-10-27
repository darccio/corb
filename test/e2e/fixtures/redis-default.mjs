import fs from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";

const expected = process.argv[1] !== "negative";
const assert = (condition, message) => { if (!condition) throw Error(message); };
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const config = fs.readFileSync("/etc/redis.conf");
const setting = (name) => config.toString().split("\n").find((line) => line.startsWith(name + " "))?.slice(name.length + 1).trim();
assert(setting("unixsocket") === "/run/redis/redis.sock" && setting("logfile") === "/var/log/redis/redis.log" && setting("dir") === "/var/lib/redis", "unexpected real packaged paths");
const user = fs.readFileSync("/etc/passwd", "utf8").trim().split("\n").map((line) => line.split(":")).find((row) => row[0] === "redis");
const group = fs.readFileSync("/etc/group", "utf8").trim().split("\n").map((line) => line.split(":")).find((row) => row[0] === "redis");
assert(user && group, "packaged redis accounts absent");
const uid = Number(user[2]); const gid = Number(group[2]);
const directories = ["/run/redis", "/var/log/redis"].map((filename) => {
  let stat; try { stat = fs.lstatSync(filename); } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (expected) assert(stat?.isDirectory() && !stat.isSymbolicLink() && stat.uid === uid && stat.gid === gid && (stat.mode & 0o777) === 0o755, `production restoration missing ${filename}`);
  return { path: filename, exists: stat !== undefined, uid: stat?.uid, gid: stat?.gid, mode: stat && (stat.mode & 0o777) };
});
const persistent = fs.statSync("/var/lib/redis"); assert(persistent.uid === uid && persistent.gid === gid, "persistent packaged ownership changed");
const cli = (...args) => execFileSync("/usr/local/bin/dropcap", ["1000", "1000", "/usr/bin/redis-cli", ...args], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "pipe"] }).trim();
let alreadyRunning = false; try { alreadyRunning = cli("PING") === "PONG"; } catch {}
assert(!alreadyRunning, "service started automatically before explicit invocation");
if (!expected) assert(directories.some((row) => !row.exists), "negative resume retained all required transient directories");
const child = spawn("/usr/local/bin/dropcap", [String(uid), String(gid), "/usr/bin/redis-server", "/etc/redis.conf"], { stdio: ["ignore", "pipe", "pipe"] });
let output = ""; child.stdout.on("data", (bytes) => { output = (output + bytes).slice(-16000); }); child.stderr.on("data", (bytes) => { output = (output + bytes).slice(-16000); });
let exit; const finished = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", (code, signal) => { exit = { code, signal }; resolve(exit); }); });
let ownedPid; let shutdown = false; let failure;
try {
  const deadline = Date.now() + 10_000; let pong = false;
  while (Date.now() < deadline) {
    try { pong = cli("PING") === "PONG"; } catch {}
    if (pong || (exit && (exit.code !== 0 || !expected))) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!expected) {
    assert(!pong && exit && exit.code !== 0, "negative normal invocation did not fail");
    assert(/Can't open the log file: (No such file or directory|Permission denied)/.test(output), `negative failed for an unrelated reason: ${output}`);
  } else {
    assert(pong, `ordinary packaged invocation failed: ${output}`);
    const info = cli("INFO", "server"); ownedPid = Number(/^process_id:(\d+)\r?$/m.exec(info)?.[1]);
    assert(Number.isSafeInteger(ownedPid) && ownedPid > 1, "owned Redis PID is absent");
    const status = fs.readFileSync(`/proc/${ownedPid}/status`, "utf8"); assert(new RegExp(`^Uid:\\s+${uid}\\s+${uid}\\s+${uid}\\s+${uid}$`, "m").test(status), "Redis is not running as its packaged account");
    assert(cli("SET", "corb:acceptance", "default-packaged") === "OK" && cli("GET", "corb:acceptance") === "default-packaged", "agent loopback SET/GET failed");
    cli("SHUTDOWN"); shutdown = true;
    const deadline = Date.now() + 10_000;
    while (fs.existsSync(`/proc/${ownedPid}`) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100));
    assert(!fs.existsSync(`/proc/${ownedPid}`), "ordinary shutdown did not stop owned Redis");
  }
} catch (error) { failure = error; }
finally {
  if (expected && !shutdown) { try { cli("SHUTDOWN"); } catch {} }
  if (!exit) {
    if (!shutdown) child.kill("SIGTERM");
    await Promise.race([finished, new Promise((resolve) => setTimeout(resolve, 3000))]);
    if (!exit) { child.kill("SIGKILL"); await finished; }
  }
  assert(fs.readFileSync("/etc/redis.conf").equals(config), "packaged config bytes changed");
}
if (failure) throw failure;
console.log(`CORB_REDIS_DEFAULT=${JSON.stringify({ expected, uid, gid, directories, daemonize: setting("daemonize") ?? "no (Redis default)", configSha256: hash(config), argv: ["redis-server", "/etc/redis.conf"], ownedPid, exit, output, explicitStartup: true, automaticStartup: false, shutdown })}`);
