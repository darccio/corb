# Production layer validation

Validation date: 2026-10-26.

DAR-23 starts from merged main `d65ead99b13acc0a1884d136dcdb66abf1e11ffb` after DAR-20 and DAR-22.
PR 12 was read as evidence at `2073c707cc1cdd5844e327df1d3baea60059d576`.
Its conditional installed-state delta model remains historical evidence and supplies no production branch base.

The production model shares authenticated inputs once and composes them separately on each exact local base.
The original base coherence report stays protected. Separate evidence validates the composed package database and signed additions.
See [the workflow](layers.md) for the public interfaces, trust boundaries and recovery rules.

## Measured results

Typecheck and lint pass. The full unit suite passes **1915 tests in 95 files**.
The serial real-VM suite passes **70 tests in 12 files**, with one separately gated concurrency case skipped.
That case then passes under its separate coordinator grant: **71 e2e tests pass across all 13 files** in the two runs.
The installed compiled CLI passes package coherence and all seven gates with no checkout `src` directory.

The serial run started at `be710ae`. Production source stayed unchanged through the run.
The later `d1ce0f7` test-only exceptional cleanup changes have six real subprocess regressions.
Earlier fixture failures remain in local logs. The final serial run passes the corrected exact assertions.

A later review with a clean home exposed a personal Git setting in the legacy SSH fixture.
Both its bare and working repositories now start explicitly on `main`, so the pushed branch matches the bare HEAD.
The SSH, Git-protection and local ORAS subset then passed 17 cases with a private clean home.

Every generation below has package coherence and seven-of-seven production gate success.
The tree transaction adds one package to the 75-package base. Both Go compositions retain 75 packages.
All three preserve 142 baseline native files and 38 protected nodes. The protected nodes cover relevant ancestor directories.

| Workload | Base SDK ID | Generation | Checkpoint SHA-256 |
| --- | --- | --- | --- |
| package | `8d1ad38c-602a-50b2-a6b4-247a2b6824bc` | `1c3392b5-5dcc-482c-827b-86d4b09b3cc2` | `68c5991c3896100813db5fc10b57d8da2afddd0def4a61ce65e3c84265cbe2ce` |
| go | `8d1ad38c-602a-50b2-a6b4-247a2b6824bc` | `01fdeb59-2061-4c51-946e-fceb413e2411` | `af85115107b9be54925cde0b99a2f2ca388aea5faed661160a3363bf0961afcd` |
| go | `a7cd90fa-05bc-5040-8cb8-71e3255c42d4` | `ed0239f0-43e0-4559-8dca-a20ea92bb8b5` | `b1697a384d760290a47ba4347eb2972bbe52e965a9d7432c838502ddb7ef5784` |

The package input graph is `sha256:fbf051ac6f9457e063720d19b61ff0ed89b4f3000ef0a430ba5a62281fafeb5d`.
The Go input graph is `sha256:2e4dd9fa8c4a72548a9d7efc5f3acb0f5c911e2ffb1cf3653c4e37c048405503` on both bases.
Its complete archive SHA-256 is `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`.
The immutable Go tree has 17372 entries below its separately checked destination root.

The first raw base rootfs SHA-256 is `51ebd6559b2f7ac68ee9296a73d3dc309e564209e1a64cdc7fc341cc78fdf92e`.
The second is `b1114bab74106a7ab7277afd8232406fe0709a188ac0de33a70e1ec8045fbdac`.
Each Go checkpoint has 307167534 bytes. The package checkpoint has 7143726 bytes.

Two sequential primary Go resumes each passed three Go tests, built a binary and ran its result as uid 1000.
They retained the checkpoint hash and canonical files. Separate writable caches kept the SDK tree immutable.
The same bound Go input graph composed on the second base without changing shared pins or the first pointer.

A final read-only audit rehashed input descriptors, metadata, evidence, checkpoints, trailers and canonical backing/assets for all three generations.
The canonical stock refs, raw manifests and recorded stock/coherent base assets stayed unchanged.
The installed-package verifier closed host PID 797816, with no forced cleanup or surviving children.
Private runtime directories were empty and removed after the serial and installed-package groups.

The approved concurrency group first primes personal trust in private test state, then resumes exactly two sessions with 1 GiB and two CPUs each.
Both root markers remain isolated and both workload markers report uid 1000.
Post-pair hashes match the primary checkpoint and all five canonical base assets.

| Session | Host QEMU PID | Temporary overlay |
| --- | --- | --- |
| Serial prime | 799504 | `/tmp/gondolin-disk-a4fea7a2.qcow2` |
| B | 799951 | `/tmp/gondolin-disk-d9c73175.qcow2` |
| A | 800044 | `/tmp/gondolin-disk-a95f4318.qcow2` |

All three processes and overlays are gone. The private pair runtime is empty and removed.
The final host check found no QEMU, Gondolin or Vitest process before the slot returned to the coordinator.
Verified cache objects, completed generations and local evidence remain for review. There is no automatic garbage collection.


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
| The SDK can run a short QEMU `--version` probe before starting a guest. | Ignore only that exact probe in guest resource checks. Keep every owned process in cleanup tracking and retain strict actual guest checks. |
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
Candidate `060f7a11-e879-4101-bf84-11139ea34f6b` lost both its owned builder source and partial checkpoint after the induced error.
The valid package pointer stayed at `1c3392b5-5dcc-482c-827b-86d4b09b3cc2`.

Host subprocess tests cover timeout, cancellation, parent SIGKILL, assertion failure, independent sessions and persistent discovery/identity errors.
The checkpoint cleanup unit controls only the `qemu-img` process boundary and uses real owned filesystem files and pointer checks.
Its two cases pass with an empty PATH and need no installed QEMU binary.
The serial e2e case retains the real QEMU/SDK checkpoint move fault.
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

## Commits

| Commit | Subject |
| --- | --- |
| `9c434ec` | feat(layers): add private input cache and composition preflight |
| `918c5dc` | feat(layers): authenticate APK archives and stage bounded SDK trees |
| `06dc90e` | fix(layers): preserve archive paths and reject uncertain metadata |
| `0d672de` | fix(image): ship the shared verifier as compiled JavaScript |
| `0d9ac57` | feat(layers): pin shared inputs and compose exact-base checkpoints |
| `2d17b5a` | fix(layers): bind trusted selection and immutable guest paths |
| `aacfb36` | feat(layers): transport immutable input graphs with ORAS |
| `01f9032` | fix(oci): force verified HTTPS for localhost registries |
| `93dfbc2` | feat(image): add base OCI distribution and local inspection |
| `38e86e4` | fix(layers): verify frozen defaults for bare APK hooks |
| `8952ae6` | fix(image): report completed publication and uncertain ref writes |
| `2869981` | fix(vm): drain bounded image work before staging cleanup |
| `3274534` | fix(vm): propagate cancellation received during final close |
| `fa32ef7` | docs(layers): explain shared inputs and exact-base composition |
| `be188c4` | fix(layers): own builder disks across checkpoint failures |
| `490a7ce` | test(layers): exercise production composition and recovery paths |
| `586f845` | fix(layers): bind file hashing to nonblocking regular descriptors |
| `55a63be` | test(layers): require exact rejection evidence and base bindings |
| `9830e09` | docs(layers): clarify native branch and trailer prerequisites |
| `6190b64` | fix(image): keep verifier egress protocols explicit |
| `36f69d5` | fix(image): enforce portable config agreement for exact objects |
| `f4f7c28` | test(layers): gate concurrent resumes on a separate VM slot |
| `be710ae` | test(vm): drain owned CLI descendants before another group |
| `d1ce0f7` | test(vm): bound cleanup when process discovery fails |
| `a457e68` | docs(layers): record source checks and validation boundaries |
