// Runs INSIDE the guest VM via `node /root/guest-stream-check.mjs <url>`.
//
// Consumes the local streaming test server through Node's global fetch
// (undici) and logs a timestamp for every chunk received, so we can tell
// whether Gondolin's egress mediation delivered them incrementally (spread
// out over time) or buffered the whole response and delivered it at once
// (all timestamps clustered together at the end).

const url = process.argv[2];
if (!url) {
  console.error("usage: node guest-stream-check.mjs <url>");
  process.exit(2);
}

const start = Date.now();
try {
  const res = await fetch(url);
  console.log(`[guest] response status ${res.status} at t+${Date.now() - start}ms`);
  if (!res.body) {
    console.log("[guest] no response body stream available");
    process.exit(1);
  }
  const decoder = new TextDecoder();
  let n = 0;
  for await (const chunk of res.body) {
    const t = Date.now() - start;
    const text = decoder.decode(chunk, { stream: true });
    console.log(`[guest] chunk ${n} at t+${t}ms bytes=${chunk.length} text=${JSON.stringify(text)}`);
    n++;
  }
  console.log(`[guest] stream ended at t+${Date.now() - start}ms, total chunks=${n}`);
} catch (err) {
  console.error(`[guest] fetch failed: ${err?.stack || err}`);
  if (err?.cause) {
    console.error(`[guest] cause: ${err.cause?.stack || err.cause}`);
    if (err.cause?.cause) {
      console.error(`[guest] cause.cause: ${err.cause.cause?.stack || err.cause.cause}`);
    }
  }
  process.exit(1);
}
