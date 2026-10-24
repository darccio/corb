// Real-VM proof of host-brokered OAuth (ADR 0012) for `openai-codex`, without
// a real ChatGPT account: the real Pi 1.4.0 in the guest reads the stand-in
// `auth.json` corb writes, sends its request to `chatgpt.com` carrying the
// stand-in, and the request that leaves the host carries the stored "real"
// access token instead. Nothing reaches OpenAI: the test's wrapper around the
// broker's `rewrite` captures the rewritten request and answers it itself.
//
// A second boot repeats the request with `egress.websockets = true`, to show
// the swap also applies to the WebSocket upgrade request Pi tries first.
//
// Gated on `CORB_E2E=1` like every other e2e suite. Drives `VM.create()`
// directly for the same reason `egress.e2e.ts` gives (an interactive Pi
// session cannot be scripted to exit), but uses the exact production pieces:
// `startBrokeredSession`, `buildEgressConfig`, `buildBrokeredGuestFiles`,
// `writeGuestPiAgentFiles` and `buildGuestEnv`.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { VM } from "@earendil-works/gondolin";
import { startBrokeredSession, type BrokeredSession } from "../../src/auth/broker.ts";
import { JWT_CLAIM_PATH, openaiCodexProvider } from "../../src/auth/providers/openai-codex.ts";
import { CREDENTIAL_FILE_VERSION, writeStoredCredential } from "../../src/auth/store.ts";
import type { EffectiveEgressConfig } from "../../src/config/load.ts";
import { createAuditWriter, type AuditWriter } from "../../src/policy/audit.ts";
import { buildEgressConfig } from "../../src/vm/egress.ts";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import {
  buildBrokeredGuestFiles,
  buildGuestEnv,
  guestPiAgentDir,
  parseCorbImageJson,
  writeGuestPiAgentFiles,
  type CorbImageJson,
} from "../../src/vm/session.ts";

const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const ACCOUNT_ID = `acct-${crypto.randomUUID()}`;
const REAL_REFRESH = `real-refresh-${crypto.randomUUID()}`;
/** Shaped like a real access token (base64url, signed-looking) so the broker and Pi treat it as one. */
const REAL_ACCESS = (() => {
  const enc = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${enc({ alg: "RS256", typ: "JWT" })}.${enc({ [JWT_CLAIM_PATH]: { chatgpt_account_id: ACCOUNT_ID }, nonce: crypto.randomUUID() })}.real-signature`;
})();
// Any model id in Pi 1.4.0's openai-codex catalog; the fake upstream answers before it matters.
const MODEL = "gpt-6.1-sol";

interface Captured {
  url: string;
  method: string;
  authorization: string | null;
  accountId: string | null;
  upgrade: string | null;
}

interface BootedSession {
  vm: VM;
  broker: BrokeredSession;
  identity: CorbImageJson;
  guestEnv: Record<string, string>;
  captured: Captured[];
  tmpDir: string;
}

/** Boots a VM wired exactly as a brokered `corb run` session, except that chatgpt.com requests are captured and answered locally. */
async function bootBrokeredSession(websockets: boolean): Promise<BootedSession> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-brokered-"));
  const credentialsDir = path.join(tmpDir, "credentials");
  writeStoredCredential(credentialsDir, {
    version: CREDENTIAL_FILE_VERSION,
    provider: "openai-codex",
    type: "oauth",
    access: REAL_ACCESS,
    refresh: REAL_REFRESH,
    expires: Date.now() + 3_600_000,
    accountId: ACCOUNT_ID,
    updatedAt: new Date().toISOString(),
  });
  const audit: AuditWriter = createAuditWriter({ path: path.join(tmpDir, "audit.jsonl") });
  const broker = await startBrokeredSession(openaiCodexProvider, {
    dir: credentialsDir,
    onSecrets: (values) => audit.addRedactedSecrets(values),
  });

  const captured: Captured[] = [];
  // The production rewrite, plus a capture-and-answer step so nothing goes to the real chatgpt.com.
  const capturing: Pick<BrokeredSession, "rewrite" | "noteResponse"> = {
    async rewrite(req) {
      const out = await broker.rewrite(req);
      if (out instanceof Request && new URL(out.url).hostname === "chatgpt.com") {
        captured.push({
          url: out.url,
          method: out.method,
          authorization: out.headers.get("authorization"),
          accountId: out.headers.get("chatgpt-account-id"),
          upgrade: out.headers.get("upgrade"),
        });
        return new Response(JSON.stringify({ error: { message: "corb e2e fake upstream", type: "invalid_request_error" } }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      return out;
    },
    noteResponse: (res, req) => broker.noteResponse(res, req),
  };

  const egress: EffectiveEgressConfig = { allow: ["chatgpt.com"], "block-internal-ranges": true, websockets };
  const egressConfig = buildEgressConfig(egress, undefined, {}, audit, "corb-e2e-brokered", undefined, [], undefined, capturing);

  const vm = await VM.create({
    sandbox: { imagePath: resolveRuntimeImage().assetDir },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks: egressConfig.httpHooks,
    env: egressConfig.env,
    allowWebSockets: egressConfig.allowWebSockets,
    sessionLabel: "corb-e2e-brokered",
  });

  const imageJson = await vm.exec(["/bin/cat", "/etc/corb/image.json"], { env: { PATH: BASE_PATH }, stdout: "buffer", stderr: "buffer" });
  const identity = parseCorbImageJson(imageJson.stdout);
  const guestEnv = buildGuestEnv(egressConfig.env, {}, identity);
  await writeGuestPiAgentFiles(vm, identity, buildBrokeredGuestFiles(broker, egressConfig.allowWebSockets));
  return { vm, broker, identity, guestEnv, captured, tmpDir };
}

async function closeSession(session: BootedSession | undefined): Promise<void> {
  if (session === undefined) {
    return;
  }
  try {
    await session.vm.close();
  } finally {
    fs.rmSync(session.tmpDir, { recursive: true, force: true });
  }
}

function asAgent(session: BootedSession, argv: string[]) {
  const { vm, identity, guestEnv } = session;
  return vm.exec([identity.paths.dropcapPath, String(identity.uid), String(identity.gid), ...argv], {
    env: guestEnv,
    stdout: "buffer",
    stderr: "buffer",
  });
}

function runPi(session: BootedSession) {
  return asAgent(session, ["/usr/local/bin/pi", "--provider", "openai-codex", "--model", MODEL, "-p", "say hi"]);
}

describe.skipIf(!process.env.CORB_E2E)("host-brokered login e2e (real VM boot, real Pi)", () => {
  let session: BootedSession | undefined;

  beforeAll(async () => {
    session = await bootBrokeredSession(false);
  }, 180_000);

  afterAll(() => closeSession(session), 180_000);

  function booted(): BootedSession {
    if (session === undefined) {
      throw new Error("brokered e2e: VM was not booted (beforeAll must have failed)");
    }
    return session;
  }

  it("writes only the stand-in into Pi's agent directory, owned by the agent user", async () => {
    const s = booted();
    const agentDir = guestPiAgentDir(s.identity);
    const result = await asAgent(s, ["/bin/sh", "-c", `stat -c '%u:%g %a %n' ${agentDir} ${agentDir}/*; cat ${agentDir}/auth.json ${agentDir}/settings.json`]);
    expect(result.ok, result.stderr).toBe(true);
    expect(result.stdout).toContain(`1000:1000 700 ${agentDir}\n`);
    expect(result.stdout).toContain(`1000:1000 600 ${agentDir}/auth.json\n`);
    expect(result.stdout).toContain(`1000:1000 600 ${agentDir}/settings.json\n`);
    expect(result.stdout).toContain(s.broker.guest.standIn);
    expect(result.stdout).toContain('"transport": "sse"');
    expect(result.stdout).not.toContain(REAL_ACCESS);
    expect(result.stdout).not.toContain(REAL_REFRESH);
  });

  it("real Pi sends the stand-in over SSE, and the request leaving the host carries the real token", async () => {
    const s = booted();
    const result = await runPi(s);
    expect(s.captured.length, `pi exit ${result.exitCode}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`).toBeGreaterThan(0);
    const first = s.captured[0]!;
    expect(new URL(first.url).hostname).toBe("chatgpt.com");
    expect(new URL(first.url).pathname).toMatch(/^\/backend-api\//);
    expect(first.method).toBe("POST");
    expect(first.upgrade).toBeNull();
    expect(first.authorization).toBe(`Bearer ${REAL_ACCESS}`);
    expect(first.accountId).toBe(ACCOUNT_ID);
    // Pi surfaced the fake upstream's error rather than hanging or refreshing.
    expect(`${result.stdout}${result.stderr}`).toContain("corb e2e fake upstream");
  }, 120_000);

  it("leaves the stand-in alone over plain HTTP, even to chatgpt.com", async () => {
    const s = booted();
    const before = s.captured.length;
    await asAgent(s, [
      "/bin/sh",
      "-c",
      `curl -sS -o /dev/null --max-time 15 -H "Authorization: Bearer ${s.broker.guest.standIn}" http://chatgpt.com/backend-api/x || true`,
    ]);
    // The capture step records every chatgpt.com request; this one must still carry the stand-in.
    const plain = s.captured.slice(before);
    expect(plain.length).toBe(1);
    expect(new URL(plain[0]!.url).protocol).toBe("http:");
    expect(plain[0]!.authorization).toBe(`Bearer ${s.broker.guest.standIn}`);
  }, 60_000);
});

describe.skipIf(!process.env.CORB_E2E)("host-brokered login e2e with egress.websockets = true", () => {
  let session: BootedSession | undefined;

  beforeAll(async () => {
    session = await bootBrokeredSession(true);
  }, 180_000);

  afterAll(() => closeSession(session), 180_000);

  it("writes no settings.json, so Pi keeps its default transport", async () => {
    const s = session!;
    const result = await asAgent(s, ["/bin/sh", "-c", `ls ${guestPiAgentDir(s.identity)}`]);
    expect(result.stdout.split("\n")).not.toContain("settings.json");
  });

  it("swaps the token on Pi's WebSocket upgrade request too", async () => {
    const s = session!;
    const result = await runPi(s);
    const upgrades = s.captured.filter((c) => c.upgrade?.toLowerCase() === "websocket");
    expect(upgrades.length, `captured: ${JSON.stringify(s.captured.map((c) => ({ url: c.url, upgrade: c.upgrade })))}\nstderr: ${result.stderr}`).toBeGreaterThan(0);
    expect(upgrades[0]!.authorization).toBe(`Bearer ${REAL_ACCESS}`);
    expect(upgrades[0]!.accountId).toBe(ACCOUNT_ID);
  }, 120_000);
});
