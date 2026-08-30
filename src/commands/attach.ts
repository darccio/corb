// `corb attach <session>` — M8.7: opens a brand-new interactive shell
// alongside a running session's own Pi process. It is emphatically **not** a
// way to rejoin Pi's own TUI/session — the raw sandbox control protocol has
// no "list execs" and no "join exec N" message, so that is not something any
// implementation of this command could offer (see `src/vm/attach.ts`'s
// module comment for the full reasoning and the spike evidence behind it).
//
// Thin CLI wiring only, mirroring `src/commands/kill.ts`'s
// `parseKillArgs`/`runKillCommand` shape closely: parse exactly one
// positional, resolve it against both registries via `findSession()` +
// `listSessionSidecars()` into the same `KillLookup`-shaped structure
// `kill.ts` already builds, call `resolveAttachTarget` (`src/vm/attach.ts`),
// and either print the refusal or hand off to `runAttachSession`. Everything
// that actually matters — the protocol mechanics, the guest identity read,
// the interactive wiring, the audit event — lives in `src/vm/attach.ts`;
// this module's only job is turning `process.argv` into a call into it and
// `process.exitCode` back out.
import { parseArgs } from "node:util";
import { findSession, type SessionEntry } from "@earendil-works/gondolin";
import { listSessionSidecars, sessionSidecarPath } from "../vm/registry.ts";
import { createAuditWriter } from "../policy/audit.ts";
import { renderAttachRefusal, resolveAttachTarget, runAttachSession } from "../vm/attach.ts";

export interface AttachCommandArgs {
  /** The session id or unambiguous id prefix the user named. Never empty. */
  session: string;
}

/**
 * `corb attach` takes exactly one positional and no flags — matching `corb
 * kill`'s own "no `--force`, keep the initial surface minimal" precedent
 * (see the M8.7 brief's "explicitly out of scope" section: no `--root`, no
 * `--command`, nothing beyond the bare `<session>` positional).
 *
 * An empty query is rejected explicitly, same reasoning `parseKillArgs`
 * documents: an empty string is a prefix of every id, so `findSession("")`
 * would happily resolve to the user's only running session.
 */
export function parseAttachArgs(argv: string[]): AttachCommandArgs {
  const { positionals } = parseArgs({ args: argv, options: {}, allowPositionals: true, strict: true });

  if (positionals.length === 0) {
    throw new Error("corb attach: missing required argument <session> (a session id, or any unambiguous id prefix — see 'corb ls')");
  }
  if (positionals.length > 1) {
    throw new Error(`corb attach: unexpected argument '${positionals[1]}' (corb attach takes exactly one session id)`);
  }
  const session = positionals[0] ?? "";
  if (session.trim().length === 0) {
    throw new Error("corb attach: <session> must not be empty (an empty query would match every session)");
  }
  return { session };
}

/**
 * The only function here that touches real global state: the real Gondolin
 * session registry, the real sidecar directory, and (via `runAttachSession`)
 * the real socket and real terminal. Everything it decides is delegated to
 * `resolveAttachTarget`; everything it does is delegated to
 * `runAttachSession` — mirroring `runKillCommand`'s own thin-orchestration
 * shape and, like it, catching `findSession()`'s ambiguous-prefix throw
 * unconditionally rather than sniffing its message (see `runKillCommand`'s
 * own doc comment for why that is the safer failure mode).
 *
 * Unlike `runKillCommand`, sidecars are read unconditionally (not only when
 * Gondolin has no match): a `connect` plan still needs its sidecar looked up
 * afterward, to find the session's `auditPath` for the one audit event this
 * command records on a successful attach. There is no TOCTOU-window
 * argument for skipping it here the way there is for `kill`'s signal path —
 * reading sidecars does not itself act on anything.
 */
export async function runAttachCommand(argv: string[]): Promise<void> {
  let args: AttachCommandArgs;
  try {
    args = parseAttachArgs(argv);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
    return;
  }

  let entry: SessionEntry | null = null;
  let ambiguousMessage: string | undefined;
  try {
    entry = await findSession(args.session);
  } catch (err) {
    ambiguousMessage = err instanceof Error ? err.message : String(err);
  }

  const sidecars = listSessionSidecars();
  const plan = resolveAttachTarget(args.session, {
    entry,
    ...(ambiguousMessage !== undefined ? { ambiguousMessage } : {}),
    sidecars,
  });

  if (plan.kind !== "connect") {
    const sidecarPath = plan.kind === "sidecar-only" ? sessionSidecarPath(plan.id) : undefined;
    console.error(renderAttachRefusal(args.session, plan, sidecarPath));
    process.exitCode = 1;
    return;
  }

  // Only a session Corb itself started has a sidecar to find an audit path
  // in — a bare-SDK / gondolin-only session (`corb ls`'s own term for this
  // case) has none, and that is not a reason to refuse a legitimate
  // connect; `runAttachSession` simply skips the audit record when `audit`
  // is left `undefined`. See its own doc comment.
  const sidecar = sidecars.find((candidate) => candidate.id === plan.id);
  const audit = sidecar !== undefined ? createAuditWriter({ path: sidecar.auditPath }) : undefined;

  const outcome = await runAttachSession(plan, { ...(audit !== undefined ? { audit } : {}) });
  if (outcome.exitCode === 0) {
    console.log(outcome.message);
    return;
  }
  console.error(outcome.message);
  process.exitCode = outcome.exitCode;
}
