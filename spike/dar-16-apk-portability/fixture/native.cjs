const assert = require("node:assert/strict");
const net = require("node:net");
const fs = require("node:fs");
const { spawn, execFileSync } = require("node:child_process");
const { once } = require("node:events");
const dir = "/tmp/corb-apk-native-" + process.pid;
fs.mkdirSync(dir);
const i16 = number => { const bytes = Buffer.alloc(2); bytes.writeInt16BE(number); return bytes; };
const i32 = number => { const bytes = Buffer.alloc(4); bytes.writeInt32BE(number); return bytes; };
const text = value => Buffer.from(value + "\0");
const message = (type, ...parts) => {
  const payload = Buffer.concat(parts); return Buffer.concat([Buffer.from(type), i32(payload.length + 4), payload]);
};
function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args); let stdout = ""; let stderr = "";
    child.stdout.on("data", data => stdout += data); child.stderr.on("data", data => stderr += data);
    child.on("error", reject); child.on("exit", code => code === 0 ? resolve(stdout) : reject(new Error(command + ": " + code + " " + stderr)));
  });
}
async function main() {
  assert.equal(process.getuid(), 1000);
  fs.writeFileSync(dir + "/native-file", "portable APK inputs\n");
  const tree = JSON.parse(await run("/usr/bin/tree", ["-J", dir]));
  assert.equal(tree[0].contents[0].name, "native-file");
  const server = net.createServer(socket => {
    let startup = true; let pending = Buffer.alloc(0);
    socket.on("data", data => {
      pending = Buffer.concat([pending, data]);
      while (pending.length >= (startup ? 4 : 5)) {
        const size = pending.readInt32BE(startup ? 0 : 1) + (startup ? 0 : 1);
        if (pending.length < size) return;
        const packet = pending.subarray(0, size); pending = pending.subarray(size);
        if (startup) {
          assert.equal(packet.readInt32BE(4), 196608);
          startup = false;
          socket.write(Buffer.concat([message("R", i32(0)), message("S", text("server_version"), text("16.15")),
            message("S", text("client_encoding"), text("UTF8")), message("K", i32(1), i32(2)), message("Z", Buffer.from("I"))]));
        } else if (packet[0] === 81) {
          assert.match(packet.subarray(5).toString(), /SELECT 42/);
          socket.write(Buffer.concat([
            message("T", i16(1), text("answer"), i32(0), i16(0), i32(23), i16(4), i32(-1), i16(0)),
            message("D", i16(1), i32(2), Buffer.from("42")), message("C", text("SELECT 1")), message("Z", Buffer.from("I")),
          ]));
        } else if (packet[0] === 88) socket.end();
      }
    });
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  let pg;
  try {
    pg = await run("/usr/bin/psql", ["-X", "-tA", "host=127.0.0.1 port=" + server.address().port + " user=fixture dbname=fixture sslmode=disable", "-c", "SELECT 42"]);
    assert.equal(pg.trim(), "42");
  } finally { server.close(); await once(server, "close"); }
  const socket = dir + "/redis.sock";
  const redis = spawn("/usr/bin/redis-server", ["--port", "0", "--unixsocket", socket, "--save", "", "--appendonly", "no", "--dir", dir]);
  let redisLog = ""; redis.stdout.on("data", data => redisLog += data); redis.stderr.on("data", data => redisLog += data);
  try {
    for (let attempt = 0; !fs.existsSync(socket); attempt++) {
      if (attempt > 100 || redis.exitCode !== null) throw new Error("Redis did not start: " + redisLog);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal((await run("/usr/bin/redis-cli", ["-s", socket, "PING"])).trim(), "PONG");
    assert.equal((await run("/usr/bin/redis-cli", ["-s", socket, "SET", "portability", "same signed bytes"])).trim(), "OK");
    assert.equal((await run("/usr/bin/redis-cli", ["-s", socket, "GET", "portability"])).trim(), "same signed bytes");
  } finally { redis.kill("SIGTERM"); await once(redis, "exit"); }
  fs.writeFileSync("/work/work/apk-write-probe", "uid1000 write\n");
  const report = { uid: process.getuid(), tests: 3, tree: true, postgresqlLoopbackQuery: pg.trim(), redis: "PING/SET/GET",
    loaders: ["/usr/bin/tree", "/usr/libexec/postgresql16/psql", "/usr/bin/redis-server"].map(filename => ({
      filename, libraries: execFileSync("/lib/ld-musl-x86_64.so.1", ["--list", filename], { encoding: "utf8" }),
    })) };
  fs.writeFileSync("/work/work/native-report.json", JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
