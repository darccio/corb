import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
export default function () {
  if (process.getuid() !== 1000 || process.getgid() !== 1000) throw new Error("wrong workload identity");
  const root = "/work/project/cache";
  const env = { ...process.env, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off", GOENV: "off", GOWORK: "off", CGO_ENABLED: "0", GOFLAGS: "-p=2", GOMAXPROCS: "2", GOCACHE: root + "/build", GOMODCACHE: root + "/modules", GOPATH: root + "/work", GOBIN: root + "/bin" };
  for (const name of ["build", "modules", "work", "bin"]) fs.mkdirSync(path.join(root, name), { recursive: true });
  const run = (name, args) => execFileSync(name, args, { cwd: "/work/project", env, encoding: "utf8", timeout: 120000, maxBuffer: 1024 * 1024 });
  const version = run("go", ["version"]); const tests = run("go", ["test", "-count=1", "-v", "./..."]);
  run("go", ["build", "-o", env.GOBIN + "/summary", "."]); const output = run(env.GOBIN + "/summary", []);
  if (output.trim() !== "42" || (tests.match(/--- PASS:/g) ?? []).length !== 3) throw new Error("Go workload failed");
  for (const action of [() => fs.writeFileSync("/opt/corb/toolchains/go/write-probe", "bad"), () => fs.renameSync("/opt/corb/toolchains/go", "/opt/corb/toolchains/go-moved"), () => fs.renameSync("/usr/local/bin/git", "/usr/local/bin/git-moved")]) {
    let denied = false; try { action(); } catch (error) { if (["EACCES", "EPERM", "EROFS"].includes(error.code)) denied = true; else throw error; }
    if (!denied) throw new Error("immutable guest path was writable");
  }
  run("/bin/sh", ["-c", "for name in npm npx su sudo doas apk apk.static; do if command -v \"$name\" >/dev/null 2>&1; then exit 1; fi; done; exit 0"]);
  const runtime = fs.statSync("/run/go-work"); if (runtime.uid !== 1000 || runtime.gid !== 1000 || (runtime.mode & 0o777) !== 0o750) throw new Error("runtime directory was not restored");
  fs.writeFileSync("/work/project/result.json", JSON.stringify({ uid: process.getuid(), version, tests, output, path: process.env.PATH, runtime: { uid: runtime.uid, gid: runtime.gid, mode: runtime.mode & 0o777 } }));
  console.log("CORB_GO_WORKLOAD_OK"); process.exit(0);
}
