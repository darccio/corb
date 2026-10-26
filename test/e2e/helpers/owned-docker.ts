import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

interface Mount { Source: string; Destination: string }
export function ownedBuildMounts(mounts: Mount[], output: string, temporary: string): boolean {
  return mounts.some((mount) => mount.Destination === "/output" && mount.Source === output)
    && mounts.some((mount) => mount.Destination === "/work" && path.dirname(mount.Source) === temporary && /^gondolin-build-[A-Za-z0-9]+$/.test(path.basename(mount.Source)));
}
export class OwnedDockerBuild {
  readonly containers = new Map<string, Mount[]>();
  private readonly before: Set<string>;
  private readonly output: string; private readonly temporary: string; private readonly env: NodeJS.ProcessEnv;
  constructor(output: string, temporary: string, env: NodeJS.ProcessEnv) { this.output = output; this.temporary = temporary; this.env = env; this.before = new Set(this.ids()); }
  private command(args: string[]) { return execFileSync("docker", args, { env: this.env, encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }); }
  private ids() { return this.command(["ps", "--all", "--no-trunc", "--format", "{{.ID}}"]).trim().split("\n").filter(Boolean); }
  sample() {
    for (const id of this.ids()) {
      if (this.before.has(id) || this.containers.has(id)) continue;
      if (!/^[a-f0-9]{64}$/.test(id)) throw Error("uncertain Docker container identity");
      let mounts: Mount[];
      try { mounts = JSON.parse(this.command(["inspect", "--format", "{{json .Mounts}}", id])); }
      catch (error) { if (!this.ids().includes(id)) continue; throw error; }
      if (ownedBuildMounts(mounts, this.output, this.temporary)) this.containers.set(id, mounts);
    }
  }
  cleanup() {
    this.sample(); const stopped: string[] = [];
    for (const [id, mounts] of this.containers) {
      if (!this.ids().includes(id)) continue;
      const current = JSON.parse(this.command(["inspect", "--format", "{{json .Mounts}}", id])) as Mount[];
      if (!ownedBuildMounts(current, this.output, this.temporary) || JSON.stringify(current) !== JSON.stringify(mounts)) throw Error("owned Docker mount identity changed");
      this.command(["stop", "--time", "5", id]);
      if (this.ids().includes(id)) this.command(["rm", id]);
      if (this.ids().includes(id)) throw Error("owned Docker build container survived cleanup");
      stopped.push(id);
    }
    return stopped;
  }
  record(filename: string, stopped: string[]) { fs.writeFileSync(filename, JSON.stringify({ containers: [...this.containers].map(([id, mounts]) => ({ id, mounts })), stopped }, null, 2), { mode: 0o600 }); }
}
