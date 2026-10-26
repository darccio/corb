import fs from "node:fs";
export default async function () {
  if (process.getuid() !== 1000) throw Error("wrong concurrent workload uid");
  const token = process.argv.at(-1);
  if (token === "prime") { console.log("CORB_RESUME_PRIMED"); process.exit(0); }
  if (!["A", "B"].includes(token)) throw Error("unknown concurrency token");
  const marker = "/home/agent/corb-resume-marker";
  fs.writeFileSync(marker, token);
  fs.writeFileSync(`/work/project/concurrent-${token}.started`, token);
  const deadline = Date.now() + 30000;
  while (!["A", "B"].every((name) => fs.existsSync(`/work/project/concurrent-${name}.started`))) {
    if (Date.now() >= deadline) throw Error("other session did not reach the barrier");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  await new Promise((resolve) => setTimeout(resolve, 1000));
  if (fs.readFileSync(marker, "utf8") !== token) throw Error("session root writes crossed overlays");
  fs.writeFileSync(`/work/project/concurrent-${token}.json`, JSON.stringify({ token, uid: process.getuid() }));
  console.log(`CORB_RESUME_ISOLATED_${token}`); process.exit(0);
}
