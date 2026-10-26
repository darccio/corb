import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const basePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const forbidden = ["npm", "npx", "su", "sudo", "doas", "apk", "apk.static"];
const protectedRoots = ["/init", "/usr/local/bin/dropcap", "/usr/local/libexec/policygate", "/usr/local/libexec/real-git", "/usr/local/libexec/real-gh", "/usr/local/bin/git", "/usr/local/bin/gh", "/usr/bin/bindfs", "/etc/corb", "/etc/apk/keys", "/usr/local/libexec/corb-package-coherence.mjs"];
function assert(condition, message) { if (!condition) throw new Error(message); }
function exists(filename) { try { return fs.lstatSync(filename); } catch (error) { if (error.code === "ENOENT") return undefined; throw error; } }
function walk(root, visit) {
  const stat = fs.lstatSync(root);
  visit(root, stat);
  if (stat.isDirectory()) for (const name of fs.readdirSync(root).sort()) walk(path.join(root, name), visit);
}
function attributes(filename, stat = fs.lstatSync(filename)) {
  assert(stat.isFile() || stat.isDirectory() || stat.isSymbolicLink(), `unsupported protected node ${filename}`);
  return { path: filename, type: stat.isSymbolicLink() ? "link" : stat.isDirectory() ? "directory" : "file", mode: stat.mode & 0o7777, uid: stat.uid, gid: stat.gid,
    ...(stat.isFile() ? { sha256: digest(fs.readFileSync(filename)) } : {}), ...(stat.isSymbolicLink() ? { link: fs.readlinkSync(filename) } : {}) };
}
export function accounts() {
  function parse(filename, group) {
    const names = new Set();
    return fs.readFileSync(filename, "utf8").trim().split("\n").map((line) => {
      const fields = line.split(":");
      const name = fields[0];
      assert(/^[a-z_][a-z0-9_-]*[$]?$/.test(name) && !names.has(name), `invalid or duplicate account ${name}`);
      names.add(name);
      const id = Number(fields[2]);
      assert(/^\d+$/.test(fields[2]) && Number.isSafeInteger(id) && id >= 0 && id <= 2147483647, `invalid account ID ${name}`);
      if (id === 0) assert(name === "root", `additional root account ${name}`);
      if (group) return { name, id };
      const gid = Number(fields[3]);
      assert(/^\d+$/.test(fields[3]) && Number.isSafeInteger(gid) && gid >= 0 && gid <= 2147483647, `invalid group ID ${name}`);
      return { name, id, gid, home: fields[5], shell: fields[6] };
    });
  }
  return { users: parse("/etc/passwd", false), groups: parse("/etc/group", true) };
}
function accountMapping(plan, actual) {
  return plan.map((entry) => {
    const user = actual.users.filter((row) => row.name === entry.owner);
    const group = actual.groups.filter((row) => row.name === entry.group);
    assert(user.length === 1 && group.length === 1, `runtime account missing ${entry.path}`);
    assert(actual.users.filter((row) => row.id === user[0].id).length === 1 && actual.groups.filter((row) => row.id === group[0].id).length === 1, `runtime account ID is ambiguous ${entry.path}`);
    return { path: entry.path, owner: entry.owner, group: entry.group, uid: user[0].id, gid: group[0].id, mode: entry.mode };
  });
}
export function restoreRuntimeDirs(plan, expected) {
  assert(Array.isArray(plan), "invalid runtime directory plan");
  const seen = new Set();
  for (const entry of plan) {
    assert(Object.keys(entry).every((key) => ["path", "mode", "owner", "group"].includes(key)), "unknown runtime field");
    assert(typeof entry.path === "string" && /^\/(?:run|var\/log)\/.+/.test(entry.path) && path.posix.normalize(entry.path) === entry.path && !entry.path.endsWith("/") && !entry.path.includes("\0") && !entry.path.includes("\\"), "invalid runtime path");
    assert(!seen.has(entry.path) && /^0[0-7]{3}$/.test(entry.mode), "invalid runtime mode or duplicate path");
    for (const root of ["/run/gondolin", "/run/corb", "/mnt/corb-raw-gate", "/mnt/corb-raw", "/etc/gondolin", "/home/agent/.pi"]) assert(entry.path !== root && !entry.path.startsWith(root + "/") && !root.startsWith(entry.path + "/"), "forbidden runtime root");
    seen.add(entry.path);
  }
  const mapping = accountMapping(plan, accounts());
  if (expected !== undefined) assert(JSON.stringify(mapping) === JSON.stringify(expected), "runtime account mapping changed");
  const mounts = fs.readFileSync("/proc/self/mountinfo", "utf8").trim().split("\n").map((line) => line.split(" ")[4].replaceAll("\\040", " "));
  for (const entry of mapping) {
    const root = entry.path.startsWith("/run/") ? "/run" : "/var/log";
    const relative = path.posix.relative(root, entry.path);
    let current = "/";
    for (const component of entry.path.split("/").filter(Boolean)) {
      current = path.posix.join(current, component);
      let stat = exists(current);
      if (stat === undefined) {
        assert(current !== root && current.startsWith(root + "/"), "runtime parent is missing");
        fs.mkdirSync(current, { mode: 0o755 }); stat = fs.lstatSync(current);
      }
      assert(stat.isDirectory() && !stat.isSymbolicLink() && fs.realpathSync(current) === current, `unsafe runtime parent ${current}`);
      if (current.startsWith(root + "/")) assert(!mounts.some((mount) => mount === current || (mount.startsWith(root + "/") && current.startsWith(mount + "/"))), "runtime path crosses a mount");
    }
    assert(!relative.startsWith("../") && relative !== "", "runtime containment failure");
    fs.chownSync(entry.path, entry.uid, entry.gid);
    fs.chmodSync(entry.path, Number.parseInt(entry.mode, 8));
  }
  return mapping;
}
function protectedFiles() {
  const files = [];
  for (const root of protectedRoots) walk(root, (filename, stat) => files.push(attributes(filename, stat)));
  return files;
}
function nativeFiles() {
  const files = [];
  for (const root of ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/lib", "/usr/local/libexec"]) {
    if (!exists(root)) continue;
    walk(root, (filename, stat) => {
      if (!stat.isFile()) return;
      const fd = fs.openSync(filename, "r"); const magic = Buffer.alloc(4);
      try { fs.readSync(fd, magic, 0, 4, 0); } finally { fs.closeSync(fd); }
      if (magic.toString("hex") === "7f454c46") files.push(attributes(filename, stat));
    });
  }
  return files;
}
function packageIdentities(database) {
  return database.trim().split(/\n\n+/).filter(Boolean).map((block) => {
    const fields = { D: "", p: "" };
    for (const line of block.split("\n")) if (["P", "V", "A", "C", "D", "p"].includes(line[0]) && line[1] === ":") fields[line[0]] = line.slice(2);
    return { P: fields.P, V: fields.V, A: fields.A, C: fields.C, D: fields.D, p: fields.p };
  });
}
export function snapshot() {
  const marker = JSON.parse(fs.readFileSync("/etc/corb/image.json", "utf8"));
  assert(marker.user === "agent" && marker.uid === 1000 && marker.gid === 1000 && marker.paths.dropcapPath === "/usr/local/bin/dropcap", "invalid production Corb marker");
  const database = fs.readFileSync("/lib/apk/db/installed", "utf8");
  const keys = Object.fromEntries(fs.readdirSync("/etc/apk/keys").sort().map((name) => {
    assert(/^[A-Za-z0-9][A-Za-z0-9._@+-]*$/.test(name) && fs.lstatSync(`/etc/apk/keys/${name}`).isFile(), "invalid APK trust key");
    return [name, fs.readFileSync(`/etc/apk/keys/${name}`, "utf8")];
  }));
  const alpineVersion = fs.readFileSync("/etc/alpine-release", "utf8").trim();
  const distro = /^ID=(.+)$/m.exec(fs.readFileSync("/etc/os-release", "utf8"))?.[1]?.replaceAll('"', "");
  assert(process.platform === "linux" && distro === "alpine" && /^\d+\.\d+(?:\.\d+)?$/.test(alpineVersion), "unsupported guest OS or Alpine release");
  return { os: process.platform, arch: process.arch === "x64" ? "x86_64" : process.arch === "arm64" ? "aarch64" : process.arch, alpineVersion, world: fs.readFileSync("/etc/apk/world", "utf8"), database, packages: packageIdentities(database), accounts: accounts(), keys, protected: protectedFiles(), native: nativeFiles() };
}
function compareFiles(expected) {
  for (const row of expected) assert(JSON.stringify(attributes(row.path)) === JSON.stringify(row), `protected file changed ${row.path}`);
}
export function verifyComposition(plan) {
  assert(JSON.stringify(protectedFiles()) === JSON.stringify(plan.baseline.protected), "complete protected baseline changed");
  compareFiles(plan.baseline.native);
  const actualAccounts = accounts();
  for (const kind of ["users", "groups"]) for (const account of plan.baseline.accounts[kind]) assert(JSON.stringify(actualAccounts[kind].find((entry) => entry.name === account.name)) === JSON.stringify(account), `base account changed ${account.name}`);
  assert(fs.readFileSync("/etc/apk/world", "utf8") === plan.world, "APK world changed outside the signed transaction");
  const current = packageIdentities(fs.readFileSync("/lib/apk/db/installed", "utf8"));
  assert(new Set(current.map((row) => row.P)).size === current.length && current.length === plan.baseline.packages.length + plan.additions.length, "extra or missing package identities");
  for (const before of plan.baseline.packages) assert(JSON.stringify(current.find((row) => row.P === before.P)) === JSON.stringify(before), `base package changed ${before.P}`);
  const owners = new Map(); let directory = "";
  for (const block of fs.readFileSync("/lib/apk/db/installed", "utf8").trim().split(/\n\n+/)) {
    const name = /^P:(.+)$/m.exec(block)?.[1]; directory = "";
    for (const line of block.split("\n")) {
      if (line.startsWith("F:")) directory = line.slice(2);
      else if (line.startsWith("R:")) {
        const filename = path.posix.join("/", directory, line.slice(2));
        assert(!owners.has(filename), `duplicate final APK file owner ${filename}`); owners.set(filename, name);
      }
    }
  }
  const archives = new Map(plan.archives.map((archive) => [archive.name, archive]));
  const baselineNative = new Map(plan.baseline.native.map((row) => [row.path, row]));
  const beforeOwners = new Map();
  for (const block of plan.baseline.database.trim().split(/\n\n+/)) {
    const name = /^P:(.+)$/m.exec(block)?.[1]; let parent = "";
    for (const line of block.split("\n")) { if (line.startsWith("F:")) parent = line.slice(2); else if (line.startsWith("R:")) beforeOwners.set(path.posix.join("/", parent, line.slice(2)), name); }
  }
  for (const [filename, owner] of beforeOwners) {
    const currentOwner = owners.get(filename);
    if (currentOwner === owner) continue;
    assert(plan.additions.some((row) => row.name === currentOwner) && archives.get(currentOwner)?.files.some((row) => row.path === filename), `unrecognized APK ownership change ${filename}`);
  }
  for (const [filename, owner] of owners) if (plan.additions.some((row) => row.name === owner)) assert(archives.get(owner)?.files.some((row) => row.path === filename), `APK ownership is absent from signed payload ${filename}`);

  for (const pin of plan.additions) {
    const actual = current.find((row) => row.P === pin.name); const signed = archives.get(pin.name);
    assert(actual && signed && actual.V === pin.version && actual.C === pin["apkindex-checksum"] && ["x86_64", "noarch"].includes(actual.A), `added package identity mismatch ${pin.name}`);
    assert(actual.D.split(" ").filter(Boolean).sort().join(" ") === [...signed.dependencies].sort().join(" ") && actual.p.split(" ").filter(Boolean).sort().join(" ") === [...signed.provides].sort().join(" "), `added package dependency/provider identity mismatch ${pin.name}`);
    for (const file of signed.files.filter((row) => row.native)) {
      assert(owners.get(file.path) === pin.name && digest(fs.readFileSync(file.path)) === file.sha256, `added native bytes or ownership mismatch ${file.path}`);
      const linked = execFileSync("/usr/bin/ldd", [file.path], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
      assert(!/not found|Error loading|Error relocating/.test(linked), `unresolved native dependency ${file.path}`);
      for (const match of linked.matchAll(/(?:=>\s+|^\s*)(\/[^\s()]+)/gm)) {
        const filename = fs.realpathSync(match[1]);
        const owner = owners.get(filename); const archive = archives.get(owner);
        const expected = baselineNative.get(filename)?.sha256 ?? archive?.files.find((row) => row.path === filename && row.sha256)?.sha256;
        assert(expected !== undefined && digest(fs.readFileSync(filename)) === expected, `unverified native dependency ${filename}`);
      }
    }
  }
  for (const payload of plan.payloads) {
    const expected = payload.tree.entries;
    const actual = [];
    walk(payload.destination, (filename, stat) => {
      assert(!stat.isSymbolicLink() && (stat.isDirectory() || stat.isFile()) && stat.uid === 0 && stat.gid === 0, "unsafe SDK tree");
      if (filename !== payload.destination) actual.push({ path: path.posix.relative(payload.destination, filename), type: stat.isDirectory() ? "directory" : "file", mode: stat.mode & 0o7777, size: stat.isDirectory() ? 0 : stat.size, ...(stat.isFile() ? { sha256: digest(fs.readFileSync(filename)) } : {}) });
    });
    assert(JSON.stringify(actual.sort((a, b) => a.path.localeCompare(b.path))) === JSON.stringify([...expected].sort((a, b) => a.path.localeCompare(b.path))), `SDK tree mismatch ${payload.name}`);
  }
  const toolPath = plan.payloads.flatMap((payload) => payload.path.map((entry) => path.posix.join(payload.destination, entry))).concat(basePath.split(":"));
  for (const directory of toolPath) {
    if (directory.startsWith("/opt/corb/toolchains/")) assert(fs.statSync(directory).isDirectory() && fs.realpathSync(directory) === directory && !fs.lstatSync(directory).isSymbolicLink(), "SDK PATH is missing, is not a directory or contains a symlink");
    for (const name of forbidden) assert(!exists(path.posix.join(directory, name)), `forbidden executable name ${name}`);
  }
  function resolve(name) { return toolPath.map((directory) => path.posix.join(directory, name)).find((filename) => { try { fs.accessSync(filename, fs.constants.X_OK); return true; } catch { return false; } }); }
  assert(resolve("git") === "/usr/local/bin/git" && resolve("gh") === "/usr/local/bin/gh" && resolve("dropcap") === "/usr/local/bin/dropcap", "mandatory security tools are shadowed");
  assert(!exists("/sbin/apk") && !exists("/sbin/apk.static"), "APK installer remains in checkpoint");
  const runtime = restoreRuntimeDirs(plan.runtime, plan.mapping);
  for (const root of ["/bin", "/sbin", "/usr", "/opt"]) walk(root, (filename, stat) => { if (stat.isFile()) assert((stat.mode & 0o6000) === 0, `SUID/SGID privilege restored ${filename}`); });
  return { version: 1, packages: current, accounts: actualAccounts, runtime, protected: plan.baseline.protected, payloads: plan.payloads.map((row) => ({ name: row.name, hash: row.tree.hash })), path: toolPath.join(":") };
}
export function copyPayloads(payloads) {
  for (const payload of payloads) {
    assert(payload.destination === `/opt/corb/toolchains/${payload.name}` || payload.destination.startsWith(`/opt/corb/toolchains/${payload.name}/`), "unsafe SDK destination");
    assert(!exists(payload.destination), "SDK destination already exists");
    let parent = path.posix.dirname(payload.destination);
    while (parent !== "/") { const stat = exists(parent); assert(stat === undefined || (stat.isDirectory() && !stat.isSymbolicLink()), "unsafe SDK parent"); parent = path.posix.dirname(parent); }
    fs.mkdirSync(payload.destination, { recursive: true, mode: 0o755 });
    for (const entry of payload.tree.entries) {
      const target = path.posix.join(payload.destination, entry.path);
      assert(target.startsWith(payload.destination + "/"), "SDK copy escaped destination");
      fs.mkdirSync(path.posix.dirname(target), { recursive: true, mode: 0o755 });
      if (entry.type === "directory") fs.mkdirSync(target, { recursive: true, mode: 0o755 });
      else { fs.copyFileSync(`/corb-layer-input/sdk/${payload.name}/${entry.path}`, target, fs.constants.COPYFILE_EXCL); fs.chownSync(target, 0, 0); fs.chmodSync(target, entry.mode); }
    }
    walk(payload.destination, (filename, stat) => { if (stat.isDirectory()) { fs.chownSync(filename, 0, 0); fs.chmodSync(filename, 0o555); } });
  }
}
export function cleanupInstaller() {
  for (const directory of basePath.split(":")) for (const name of forbidden) {
    const filename = path.posix.join(directory, name); const stat = exists(filename);
    if (stat) { assert(!stat.isDirectory(), `forbidden name is a directory ${filename}`); fs.unlinkSync(filename); }
  }
}
const apkContextPath = "/run/corb-layer-apk-context";
const apkContextFiles = ["/etc/apk/config", "/etc/apk/repositories"];
function apkContextStart() {
  assert(!exists(apkContextPath) && !exists("/sbin/apk"), "APK transaction context already exists");
  fs.mkdirSync(apkContextPath, { mode: 0o700 });
  const previous = apkContextFiles.map((filename) => {
    const stat = exists(filename);
    assert(stat === undefined || (stat.isFile() && !stat.isSymbolicLink()), "unsafe APK configuration node");
    return { filename, ...(stat === undefined ? { absent: true } : { bytes: fs.readFileSync(filename).toString("base64"), mode: stat.mode & 0o7777, uid: stat.uid, gid: stat.gid }) };
  });
  fs.writeFileSync(`${apkContextPath}/previous.json`, JSON.stringify(previous), { flag: "wx", mode: 0o600 });
  try {
    for (const filename of apkContextFiles) if (exists(filename)) fs.unlinkSync(filename);
    fs.writeFileSync("/etc/apk/config", "no-network\nrepositories-file /corb-layer-input/repositories.list\n", { flag: "wx", mode: 0o600 });
    fs.writeFileSync("/etc/apk/repositories", fs.readFileSync("/corb-layer-input/repositories.list"), { flag: "wx", mode: 0o600 });
    fs.symlinkSync("/corb-layer-input/bin/apk.static", "/sbin/apk");
  } catch (error) { apkContextEnd(); throw error; }
}
function apkContextEnd() {
  try { if (exists("/sbin/apk")) fs.unlinkSync("/sbin/apk"); }
  finally {
    const previous = JSON.parse(fs.readFileSync(`${apkContextPath}/previous.json`, "utf8"));
    for (const row of previous) {
      assert(apkContextFiles.includes(row.filename), "unsafe APK restoration target");
      if (exists(row.filename)) fs.unlinkSync(row.filename);
      if (!row.absent) { fs.writeFileSync(row.filename, Buffer.from(row.bytes, "base64"), { flag: "wx", mode: row.mode }); fs.chownSync(row.filename, row.uid, row.gid); fs.chmodSync(row.filename, row.mode); }
    }
    fs.rmSync(apkContextPath, { recursive: true });
  }
}
function processIdentities() {
  const result = {};
  for (const name of fs.readdirSync("/proc")) {
    if (!/^[1-9][0-9]*$/.test(name) || Number(name) === process.pid) continue;
    try {
      const text = fs.readFileSync(`/proc/${name}/stat`, "utf8");
      const fields = text.slice(text.lastIndexOf(") ") + 2).split(" ");
      if (fs.readFileSync(`/proc/${name}/cmdline`).length > 0) result[name] = fields[19];
    } catch (error) { if (error.code !== "ENOENT" && error.code !== "ESRCH") throw error; }
  }
  return result;
}
async function stopProcesses(before) {
  const excluded = new Set(["1"]); let pid = process.pid;
  while (pid > 1) { excluded.add(String(pid)); const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8"); pid = Number(text.slice(text.lastIndexOf(") ") + 2).split(" ")[1]); }
  const candidates = Object.entries(processIdentities()).filter(([name, start]) => !excluded.has(name) && before[name] !== start);
  for (const [name] of candidates) { try { process.kill(Number(name), "SIGTERM"); } catch (error) { if (error.code !== "ESRCH") throw error; } }
  if (candidates.length > 0) await new Promise((resolve) => setTimeout(resolve, 250));
  let actual = processIdentities();
  for (const [name, start] of candidates) if (actual[name] === start) { try { process.kill(Number(name), "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; } }
  if (candidates.length > 0) await new Promise((resolve) => setTimeout(resolve, 250));
  actual = processIdentities();
  for (const [name, start] of candidates) assert(actual[name] !== start, `service process did not stop ${name}`);
}
function recordEvidence(evidence) {
  const directory = "/var/lib/corb-layer";
  for (const parent of ["/var", "/var/lib"]) assert(fs.lstatSync(parent).isDirectory() && fs.realpathSync(parent) === parent, "unsafe composition evidence parent");
  assert(!exists(directory), "composition evidence directory already exists"); fs.mkdirSync(directory, { mode: 0o700 });
  const bytes = JSON.stringify(evidence); fs.writeFileSync(`${directory}/composition.json`, bytes, { flag: "wx", mode: 0o400 });
  return { sha256: digest(bytes) };
}
function checkEvidence() {
  const filename = "/var/lib/corb-layer/composition.json"; const stat = fs.lstatSync(filename);
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 && stat.gid === 0 && (stat.mode & 0o7777) === 0o400, "unsafe composition evidence");
  return { sha256: digest(fs.readFileSync(filename)) };
}
if (process.argv[1] === "--corb-layer-internal") {
  const action = process.argv[2]; const input = JSON.parse(fs.readFileSync(0, "utf8")); let result;
  if (action === "snapshot") result = snapshot();
  else if (action === "processes") result = processIdentities();
  else if (action === "stop") { await stopProcesses(input); result = { ok: true }; }
  else if (action === "apk-context-start") { apkContextStart(); result = { ok: true }; }
  else if (action === "apk-context-end") { apkContextEnd(); result = { ok: true }; }
  else if (action === "record") result = recordEvidence(input);
  else if (action === "record-check") result = checkEvidence();
  else if (action === "database") result = { database: fs.readFileSync("/lib/apk/db/installed", "utf8"), world: fs.readFileSync("/etc/apk/world", "utf8") };
  else if (action === "runtime") result = restoreRuntimeDirs(input.plan, input.expected);
  else if (action === "copy") { copyPayloads(input); result = { ok: true }; }
  else if (action === "clean") { cleanupInstaller(); result = { ok: true }; }
  else if (action === "verify") result = verifyComposition(input);
  else throw new Error("unknown internal layer operation");
  console.log(JSON.stringify(result));
}
