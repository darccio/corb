# Production layer validation

Validation date: 2026-10-26.

DAR-23 starts from merged main `d65ead99b13acc0a1884d136dcdb66abf1e11ffb` after DAR-20 and DAR-22.
PR 12 was read as evidence at `2073c707cc1cdd5844e327df1d3baea60059d576`.
Its conditional installed-state delta model remains historical evidence and supplies no production branch base.

The production model shares authenticated inputs once and composes them separately on each exact local base.
The original base coherence report stays protected. Separate evidence validates the composed package database and signed additions.
See [the workflow](layers.md) for the public interfaces, trust boundaries and recovery rules.

## Source checks and decisions

The following details came from the installed Gondolin 0.12.0 source, APK 3.0.8 source or real commands.
They explain implementation choices and corrections to earlier assumptions.

| Source reality | Production response |
| --- | --- |
| The SDK trailer loader checks safe integers and file bounds but has no small metadata cap. | Bound trailers to 64 KiB before the SDK loader. Require a regular non-symlink descriptor opened without blocking. |
| SDK resume can rebase a checkpoint in place when resolved backing path spelling differs. | Require the exact direct canonical raw-base backing before SDK resume. Reject changes instead of repairing them. |
| A live checkpoint retains the builder's clone options. | Reload stored bytes and provide complete verifier or normal session options. |
| SDK checkpoint disables source deletion before moving the disk and writing the trailer. | Keep owned builder and checkpoint files in the unpublished generation directory. An induced real SDK move failure must clean both. |
| The seven gates explicitly use the base PATH. | Check the complete SDK PATH separately and preserve it in Pi. |
| The ordinary base PATH can include an absent `/usr/local/sbin`. | Require declared SDK PATH directories to exist, while preserving normal base behavior. |
| Large Go tree plans exceed Linux's single-argument limit. | Send bounded internal plans through stdin, rather than one command argument. |
| APK recursive fetch collects candidates without installed state and ignores conflicts. | Resolve the complete candidate closure, then separately simulate the actual exact requested add against the selected base. |
| APK can print query errors while returning zero. Its version includes the package revision, summaries use decimal MiB, and local repository URLs append the architecture. | Validate every query row and transaction operation, exact installer version and frozen repository layout. |
| Signed Alpine key names include `@`. Indexes also contain unrelated uppercase names and large package records. | Accept authentic index syntax, but bound and authenticate every selected archive separately. |
| Parent APK options and APK environment variables do not survive into bare signed hooks. | Temporarily install frozen no-network repository defaults. Prove a sanitized bare child uses them and restore original bytes, modes and absence afterward. |
| APK can change ownership tables without changing existing package identities. | Compare canonical P/V/A/C/D/p identities and final ownership/coherence, rather than complete database serialization. |
| Installed npm packages ship `dist` and `image`, without checkout `src`. Node refuses TypeScript stripping under `node_modules`. | Compile the single shared verifier to JavaScript and keep checkout-only bridges thin. Test a real installed package without `src`. |
| ORAS 1.3.5 reports a text version and requires an explicit blob-fetch output option. Copy TLS/auth flags use direction prefixes. | Check the exact version, fetch blobs with `--output -`, and pass flags to the correct remote side. |
| ORAS 1.3.5 defaults localhost registries to HTTP even when the option is omitted. | Pass explicit false-valued plain-HTTP options. This disables HTTP and is the necessary exception to the prompt's literal flag wording. Never enable HTTP or insecure TLS. |
| SDK verification wrappers otherwise inherit WebSocket allowance. | Explicitly disable WebSockets and SSH egress for image verification. |
| SDK exit hooks do not guarantee child reaping after a parent SIGKILL. | The test runner tracks owned sessions and process start identities, drains verified children and bounds escalation. Discovery uncertainty fails the group. |
| The installed canonical `corb:0.1.0` still lacks the new coherence report. | Preserve that canonical ref and its assets. Use independently rebuilt coherent bases and private SDK stores for validation. |

The two tested bases have different rootfs bytes and SDK IDs but the same package and account state.
This proves separate exact-base caches over reusable inputs.
It does not establish DAR-21's stronger different-package/account-state acceptance.

## Evidence boundaries

The real package recipe requests `tree=2.2.1-r0`.
Its candidate bundle includes musl even though the base already supplies it. The actual transaction adds only tree and runs signed triggers.
The Go recipe has `packages = []` and a complete verified Go 1.27.3 SDK archive.

The serial lifecycle tests use production pin/build/run paths, uid 1000, workspace mounts and separate writable Go caches.
They set `GOTOOLCHAIN=local` and check installer absence, immutable SDK trees, protected paths and named runtime directories.
A cached bound pull must work without ORAS or a VM. Another compatible exact base must reuse the same locked input digest.

Negative controls require the executed root step and the specific intended detector error.
They cover SDK root and ancestor modes, security-tool ancestors, protected file bytes, a new unprotected SUID executable and a copied authenticated installer.
Checkpoint-byte tampering, foreign generation base metadata and direct backing mutation have separate preflight assertions before VM creation.
Foreign embedded trailer IDs have separate unit coverage.

A real SDK checkpoint move fault tests owned disk cleanup and preservation of the previous current pointer.
Host subprocess tests cover timeout, cancellation, parent SIGKILL, assertion failure, independent sessions and persistent discovery/identity errors.
A separate concurrency test stays disabled until the coordinator grants a two-VM slot after checking resources and backing.

Local ORAS layout copies, exact CLI contracts, HTTPS scheme selection and real cancellation are transport checks.
The 30-minute watchdog uses controlled time. The suite does not wait 30 real minutes to establish it.
Neither local copies nor mocks establish remote Distribution API/auth acceptance.
DAR-21 owns that HTTPS producer/recipient flow and real packaged Redis startup checks.

## Repeat the checks

Use private `CORB_CONFIG_DIR`, `CORB_STATE_DIR`, `CORB_CACHE_DIR`, `GONDOLIN_IMAGE_STORE` and a short private `GONDOLIN_SESSIONS_DIR`.
Import a coherent base and create any default alias only inside that private SDK store.
Never retag the real canonical image during validation.
Start with the coordinator's exclusive serial VM slot and no live provider credentials or personal mounts.

Run `npm run typecheck`, `npm run lint`, `npm test` and `CORB_E2E=1 npm run test:e2e`.
For layer validation, set `CORB_E2E_LAYER_BASE` to the first coherent base and `CORB_E2E_LAYER_SECOND_BASE` to another compatible coherent base.
Set `CORB_E2E_LAYER_ROOT` to private disk-backed artifact storage. The fixture creates fresh config, state, cache and evidence below it.

The optional concurrency case also needs `CORB_E2E_LAYER_CONCURRENCY=1`, `CORB_E2E_LAYER_EXISTING` and `CORB_E2E_LAYER_GENERATION`.
Those last two paths select the completed lifecycle root and its primary Go generation directory.
Enable it only after a separate resource/backing preflight and explicit coordinator grant.
