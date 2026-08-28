// `src/policy/sentinel.ts` — M7.2: the `onRequest` handler for
// `docs/design.md` §5's out-of-guest content-check sentinel. Structurally
// the same kind of thing as `src/policy/github.ts`'s `githubApiGate` — an
// `onRequest` short-circuit (`createHttpHooks({ onRequest })`,
// `docs/gondolin-notes.md` §4) that returns `undefined` to mean pass-through
// and a synthetic `Response` to mean "this hook has fully handled the
// request" — except this one is `async`, because unlike `githubApiGate` it
// genuinely needs to read the request body (`req.json()`/a streamed read),
// per §5: "Reading the body with `await req.json()` is sound here:
// `onRequest` receives a full WHATWG `Request`."
//
// Wiring this into `src/vm/egress.ts`'s `onRequest` composition (alongside
// `githubApiGate`) and adding `POLICY_HOST` to `allowedHosts` is explicitly
// **not** this item's job — that is M7.3, which already has a forward
// pointer waiting for it at `src/vm/egress.ts:170-179`. This file is the
// host-side content-check service in isolation: importable and
// independently unit-testable via a synthetic `Request`, nothing more.
//
// Never bind a real secret to `POLICY_HOST` (`docs/design.md` §5: "Secrets
// may already be expanded by the time `onRequest` runs, and this handler
// reads and logs its request body") — that is enforced by how M7.3 wires
// `createHttpHooks({ secrets })`, not by anything in this file, but it is
// the reason this module never treats anything it reads from `req` as safe
// to echo back or to trust without validation.
import type { DirConfig, EffectivePolicyConfig } from "../config/load.ts";
import type { AuditWriter } from "./audit.ts";
import { runChecks, type PolicyCheckRequest, type PolicyCheckResponse, type Violation } from "./checks.ts";

/**
 * The sentinel hostname, `docs/design.md` §5: reserved by RFC 2606
 * (`.invalid` "can never resolve"), so if this `onRequest` short-circuit is
 * ever removed or bypassed, a request to this host fails to connect rather
 * than leaking the payload to a real destination. Exported as a constant
 * (rather than left as a literal buried in this file) because M7.3 needs
 * this exact string a second time, to add it to `allowedHosts` — a shared
 * source of truth beats the hostname being spelled out independently in two
 * files and trusting them to agree.
 */
export const POLICY_HOST = "policy.corb.invalid";

/**
 * `docs/design.md` §5: "Reject anything over a fixed limit (256 KiB is
 * generous for a diff)". Applies to the JSON-encoded request body as a
 * whole (not just the `diff` field) — see `readBodyWithCap` for how this is
 * enforced both by `Content-Length` and by counting streamed bytes.
 */
export const MAX_BODY_BYTES = 256 * 1024;

/**
 * Shape-validation bounds for `changedFiles`, enforced in step 4 below.
 * These are defense against a hostile or buggy guest sending a
 * pathologically shaped (but under the byte cap) body — e.g. 200,000
 * one-character entries — not a real-world limit on legitimate commits;
 * `checkChangedFileCeiling` (`checks.ts`) is the actual, configurable,
 * policy-driven ceiling on commit size. 5,000 entries and 4 KiB per path are
 * both far beyond anything a real git commit or push range would ever
 * contain (a real filesystem path rarely exceeds a few hundred bytes), so
 * neither bound is expected to ever fire on a legitimate request.
 */
const MAX_CHANGED_FILES = 5_000;
const MAX_PATH_BYTES = 4 * 1024;

/**
 * Fixed per-session rate-limit budget, checked in step 5 below. A plain
 * fixed budget with **no refill**, deliberately simpler than a token
 * bucket with a refill rate: `docs/design.md` §7's wall-clock watchdog
 * already caps how long any one session can run at all, so there is no
 * long-lived-session case here that a refill would need to account for —
 * "per session" already has a hard ceiling on it from a different
 * mechanism. 60 is deliberately generous: a real workflow issues at most
 * one content check per `git commit` or `git push`, so exhausting 60 in a
 * single interactive session means ~60 commits or pushes already happened
 * in that one session, which is already an unusual amount of git activity.
 * Exceeding the budget is a real denial (see step 5's handling below), not
 * an infrastructure hiccup, so the budget is set high enough that only
 * genuine abuse (a guest looping the request deliberately) is expected to
 * ever hit it.
 */
export const RATE_LIMIT_BUDGET = 60;

function jsonResponse(body: PolicyCheckResponse): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

/** `{ allowed: false, rateLimited: false, violations: [violation] }`, status 200. */
function denyWithViolation(violation: Violation): Response {
  return jsonResponse({ allowed: false, rateLimited: false, violations: [violation] });
}

/**
 * Best-effort `op` extraction from a value that hasn't been (or couldn't
 * be) fully shape-validated yet, for the audit `subject` field. Falls back
 * to `"unknown"` whenever `op` isn't present or isn't one of the two known
 * literals — which, for the body-size-cap denial in step 3, is always,
 * since nothing has been parsed yet at that point.
 */
function subjectFromUnvalidated(parsed: unknown): string {
  if (typeof parsed === "object" && parsed !== null) {
    const op = (parsed as Record<string, unknown>).op;
    if (op === "git.commit" || op === "git.push") {
      return op;
    }
  }
  return "unknown";
}

/**
 * Reads `req.body` (a `ReadableStream<Uint8Array>`) via its reader,
 * accumulating bytes and checking the running total against
 * `MAX_BODY_BYTES` on every chunk — never buffering a full oversized body
 * first. Per `docs/design.md` §5, this is required *in addition to* the
 * `Content-Length`-header check (done by the caller before this is ever
 * invoked), since `Content-Length` is guest-supplied and cannot be trusted
 * alone: a guest can lie about it, or omit it and stream more than it
 * claimed.
 *
 * Returns `{ ok: false }` (and cancels the reader) the moment the running
 * total exceeds the cap, without waiting for the stream to end. Returns
 * `{ ok: true, bytes }` with the fully-assembled body once the stream ends
 * within budget. A request with no body (`req.body === null`) is treated as
 * a zero-byte body, not an error — shape validation downstream will reject
 * it for not being valid JSON.
 */
async function readBodyWithCap(req: Request): Promise<{ ok: true; bytes: Uint8Array } | { ok: false }> {
  const reader = req.body?.getReader();
  if (reader === undefined) {
    return { ok: true, bytes: new Uint8Array(0) };
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel("body exceeds cap").catch(() => {
        // Best-effort cancellation; the denial below is what matters.
      });
      return { ok: false };
    }
    chunks.push(value);
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, bytes: combined };
}

/** Structural validation of a JSON-parsed value against `PolicyCheckRequest`'s exact shape. Never trusts a parsed object as-is. */
function isValidCheckRequest(value: unknown): value is PolicyCheckRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;

  if (candidate.op !== "git.commit" && candidate.op !== "git.push") {
    return false;
  }

  if (!Array.isArray(candidate.changedFiles) || candidate.changedFiles.length > MAX_CHANGED_FILES) {
    return false;
  }
  for (const entry of candidate.changedFiles) {
    if (typeof entry !== "string" || entry.length > MAX_PATH_BYTES) {
      return false;
    }
  }

  if (typeof candidate.diff !== "string") {
    return false;
  }

  return true;
}

/**
 * Builds the `onRequest` hook that implements `docs/design.md` §5's
 * out-of-guest content-check sentinel. One `sentinel()` call is expected per
 * session (matching `githubApiGate`'s own per-session closure convention),
 * which is what makes the plain, non-`Map`-based rate-limit counter below
 * safe: it is closed over inside the returned function and starts fresh
 * every time `sentinel()` itself is called, one bucket per session by
 * construction rather than by an explicit `sessionId` lookup.
 *
 * Behavior, in order — see the module-level doc comments above for the
 * constants referenced:
 *
 *   1. `policy.enabled === false` -> pass through untouched (`undefined`),
 *      no audit event. Matches `githubApiGate`'s "config-driven-only no-op"
 *      convention.
 *   2. Hostname of `req.url` isn't exactly `POLICY_HOST` -> pass through
 *      untouched, no audit event. This hook has no opinion about any other
 *      host.
 *   3. Body-size cap, checked both by `Content-Length` (denies immediately,
 *      without reading the body at all, if the header already exceeds the
 *      cap) and by counting streamed bytes (`readBodyWithCap`).
 *   4. Parse the size-bounded body as JSON, then shape-validate every field
 *      (`isValidCheckRequest`) before any of it reaches `runChecks`.
 *   5. Rate limit: a fixed per-session budget (`RATE_LIMIT_BUDGET`). Per
 *      §5, exceeding it is a genuine denial (`rateLimited: true`), not an
 *      infrastructure error — treating it as the latter would let the guest
 *      deliberately exhaust the budget to obtain fail-open on demand.
 *   6. Run `runChecks` (`checks.ts`), wrapped in `try`/`catch`:
 *        - zero violations -> allow.
 *        - one or more violations -> deny, `reason` is the comma-joined
 *          rule names only (never diff text or matched secret substrings).
 *        - `runChecks` itself throwing -> fail open when
 *          `policy["fail-open"]` is `true` (its default), fail closed
 *          otherwise. Either way the audit `reason` says loudly that the
 *          check did not run, per §5's "Failure behaviour": "the audit log
 *          records loudly that the check did not run."
 *
 * Every `Response` this function returns has `status: 200` and
 * `Content-Type: application/json`, carrying a body that always parses as a
 * valid `PolicyCheckResponse` — the HTTP status code itself carries no
 * meaning here, unlike `github.ts`'s `denyResponse` (which uses 403, a
 * different, older convention for a different gate). This is the one
 * property most worth getting exactly right:
 * `guest/internal/gate/hostcheck.go`'s `CheckContent` treats any non-2xx
 * status as a transport-level error and routes it through the guest's own
 * fail-open path, not through its "real denial" path — so an accidental
 * non-200 status here would make every genuine content-check denial look
 * like an infrastructure failure to the guest and silently fail open,
 * defeating the whole feature. Only the JSON body's `allowed` field
 * communicates the decision.
 */
export function sentinel(
  policy: EffectivePolicyConfig,
  dirs: readonly DirConfig[],
  audit: AuditWriter,
  sessionId: string,
): (req: Request) => Promise<Response | undefined> {
  // One counter per `sentinel()` call, i.e. one per session — see the doc
  // comment above and `RATE_LIMIT_BUDGET`'s own comment for why a plain
  // counter (no `Map`, no refill) is sufficient here.
  let checksUsed = 0;

  return async (req: Request): Promise<Response | undefined> => {
    if (policy.enabled === false) {
      return undefined;
    }

    const url = new URL(req.url);
    if (url.hostname !== POLICY_HOST) {
      return undefined;
    }

    // Step 3a: Content-Length, if present, is guest-supplied and checked
    // first so an already-oversized declared length is denied without
    // reading any of the body.
    const contentLengthHeader = req.headers.get("content-length");
    if (contentLengthHeader !== null) {
      const declaredLength = Number(contentLengthHeader);
      if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
        audit.record({
          channel: "gate",
          decision: "deny",
          subject: "unknown",
          reason: "request body exceeds 256 KiB cap",
          sessionId,
        });
        return denyWithViolation({
          rule: "body-too-large",
          message: "request body exceeds the 256 KiB content-check size cap",
          hint: "reduce the size of the diff or push range that triggered this check",
        });
      }
    }

    // Step 3b: count bytes as they stream, since Content-Length cannot be
    // trusted alone (it may be absent, or the guest may lie about it).
    const bodyResult = await readBodyWithCap(req);
    if (!bodyResult.ok) {
      audit.record({
        channel: "gate",
        decision: "deny",
        subject: "unknown",
        reason: "request body exceeds 256 KiB cap",
        sessionId,
      });
      return denyWithViolation({
        rule: "body-too-large",
        message: "request body exceeds the 256 KiB content-check size cap",
        hint: "reduce the size of the diff or push range that triggered this check",
      });
    }

    // Step 4: parse, then field-by-field shape-validate. An unvalidated
    // parsed object never reaches `runChecks`.
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bodyResult.bytes));
    } catch {
      audit.record({
        channel: "gate",
        decision: "deny",
        subject: "unknown",
        reason: "malformed policy check request",
        sessionId,
      });
      return denyWithViolation({
        rule: "malformed-request",
        message: "request body is not valid JSON",
        hint: "this is a corb-internal error; report it rather than retrying the same command",
      });
    }

    if (!isValidCheckRequest(parsed)) {
      audit.record({
        channel: "gate",
        decision: "deny",
        subject: subjectFromUnvalidated(parsed),
        reason: "malformed policy check request",
        sessionId,
      });
      return denyWithViolation({
        rule: "malformed-request",
        message: "request body does not match the expected policy-check shape",
        hint: "this is a corb-internal error; report it rather than retrying the same command",
      });
    }

    const checkRequest: PolicyCheckRequest = parsed;

    // Step 5: rate limit. A denial here is a real denial, never treated as
    // an infrastructure error — see this function's doc comment and
    // `RATE_LIMIT_BUDGET`'s own comment.
    checksUsed += 1;
    if (checksUsed > RATE_LIMIT_BUDGET) {
      audit.record({
        channel: "gate",
        decision: "deny",
        subject: checkRequest.op,
        reason: "rate limit exceeded",
        sessionId,
      });
      return jsonResponse({ allowed: false, rateLimited: true });
    }

    // Step 6: run the fixed check functions.
    try {
      const violations = runChecks(checkRequest, policy, dirs);

      if (violations.length === 0) {
        audit.record({
          channel: "gate",
          decision: "allow",
          subject: checkRequest.op,
          reason: "ok",
          sessionId,
        });
        return jsonResponse({ allowed: true, rateLimited: false });
      }

      const reason = violations.map((violation) => violation.rule).join(", ");
      audit.record({
        channel: "gate",
        decision: "deny",
        subject: checkRequest.op,
        reason,
        sessionId,
      });
      return jsonResponse({ allowed: false, rateLimited: false, violations });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      if (policy["fail-open"]) {
        audit.record({
          channel: "gate",
          decision: "allow",
          subject: checkRequest.op,
          reason: `content check failed to run: ${message}, failing open`,
          sessionId,
        });
        return jsonResponse({ allowed: true, rateLimited: false });
      }

      audit.record({
        channel: "gate",
        decision: "deny",
        subject: checkRequest.op,
        reason: `content check failed to run: ${message}, failing closed (policy.fail-open=false)`,
        sessionId,
      });
      return denyWithViolation({
        rule: "check-error",
        message: "the content-check service failed while evaluating this change",
        hint: "this is a corb-internal error; report it rather than retrying the same command",
      });
    }
  };
}
