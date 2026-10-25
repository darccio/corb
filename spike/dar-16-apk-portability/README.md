# APK input bundle portability trial

This experiment tests signed APK input reuse across two different Alpine-based Corb images.
It also tests full installed-state replay and separate checkpoint caches.
It adds no production command, schema, dependency or image recipe.
Production DAR-16 remains unapproved.

## Result

The same signed package bundle works on both tested bases after a separate APK transaction on each base.
Each transaction runs that base's solver, package scripts and triggers.
The resulting account IDs and config files differ correctly.
The composed checkpoints remain tied to their exact base build IDs.

Unconditional replay of the installed filesystem changes fails the consumer-state test.
It deletes a consumer account, overwrites its config and leaves data owned by an unknown UID.
The installed tools still work, and the image gates do not detect that consumer-state loss.
A preimage check rejects this replay before it changes the consumer.
This does not rule out a conditional delta when every changed or deleted path has the expected prior state.

A [separate conditional control](conditional-control.md) demonstrates that case on a different base build ID.
It changes an unrelated protected config file, then safely applies the same delta with all producer preconditions enabled.
This does not establish arbitrary scripts' read-only dependencies or a production applier.

Both bases retain stale OpenSSL package records.
Their records say `3.5.4-r0`, but their library bytes match authenticated `3.5.9-r0` APKs.
The positive result applies to these measured binaries and transactions.
It does not establish a fully consistent package database or a production-ready base.

## Necessary contract and tested subset

The [APK package format](https://raw.githubusercontent.com/alpinelinux/apk-tools/v3.0.8/doc/apk-package.5.scd) defines architecture, dependencies, providers, scripts and triggers.
The [APK add command](https://raw.githubusercontent.com/alpinelinux/apk-tools/v3.0.8/doc/apk-add.8.scd) solves against installed packages and world constraints.
The same Alpine release string alone does not settle those inputs.

| Requirement | What this trial establishes |
| --- | --- |
| Compatible distribution, architecture and libc ABI | Both bases report Alpine 3.23.0, x86_64 and musl. The native loader resolves all tested libraries. |
| Authenticated repository snapshot and package bytes | Both frozen v3.23 indexes and every consumed APK pass signatures, exact P/V/C, signed size and payload hash checks. Each base's own keys verify them. |
| Compatible installed packages, world and solver plan | A adds six packages. B already has tree and adds five. No existing package identity changes. A planned OpenSSL upgrade rejects before installation. |
| Scripts, accounts, config and runtime state | Redis chooses uid 100/gid 101 on A and preserves uid/gid 350 on B. B's consumer account, data and config survive its own transaction. |
| Corb security policy | Protected hashes remain equal. All seven forbidden names are absent after cleanup. Signed sudo fails the actual SUID and PATH gates. |
| Base metadata matches actual files | This condition is not satisfied. All three inspected bases have the OpenSSL record/byte mismatch. |
| Wider release and ABI support | Other Alpine patches, branches, architectures, libc implementations, kernels and arbitrary packages remain untested. |

The input bundle contains the installer, signed indexes and the six added package archives.
It relies on compatible packages already supplied by the base.
It is not a standalone root filesystem or an archive of every transitive runtime dependency.
Another base can require a different closure or reject the requested world.

## Bases and matrix

| Base | Build ID | Rootfs SHA-256 | Initial records |
| --- | --- | --- | --- |
| A: DAR-15 fixed | `e8292a0a-0a1a-52d5-959b-9ed372068d54` | `de13c9757a2aaef4aecbc331bbb54416940e8f0dca4367ffbd7b766e9716cec7` | 55 |
| B: isolated variant | `820396a0-70a9-5772-af9c-c1d3eba7ae8d` | `ad9b005397c08fd0e7e5f1d56bcbb719a0bde45e7e79e04f08b2d141a088fb97` | 56 |
| Stock metadata control | `2747a805-7a7e-5798-84ca-077fb5086311` | `66dcee4cc7bcc04b67f1567a806bc16e8d0c00e0b09763593f72b4841533b5cf` | 20 |

B uses the same registration recipe as DAR-15 fixed.
It adds tree, Redis uid/gid 350, a separate uid/gid 351 account, consumer data and a Redis config.
It is a new build with different actual rootfs bytes, not a renamed image.
It is imported without a tag.
The stock image is inspected as an incomplete-registration control, not used as a positive APK base.

B's synthetic Redis file contains literal backslash-n sequences, so it is a comment-only marker.
The experiment checks its byte preservation and later overwrite, not an active `port 0` setting.

The requested packages are `tree=2.2.1-r0`, `postgresql16-client=16.15-r0` and `redis=8.4.2-r0`.
Their added dependency archives are `postgresql-common=1.2-r2`, `lz4-libs=1.10.0-r0` and `libpq=18.6-r0`.
`tree` tests a small CLI and a package already present on B.
PostgreSQL tests shared-library resolution and an actual query against a local protocol fixture.
Redis tests account scripts, config preservation and a local PING/SET/GET workload.
All useful workloads run as uid 1000 through production `dropcap` and write the generated workspace.

## Script and checkpoint limits

The primary transaction keeps the authenticated installer outside `PATH` on a read-only mount.
It does not use `--allow-untrusted` or skip scripts.
The PostgreSQL trigger logs `apk: not found`, although the transaction exits zero and the query works.

A separate experiment exposes `/sbin/apk` as a temporary symlink to that external installer during the root transaction.
It removes the symlink and all forbidden names before checkpoint creation.
The trigger then has no missing-APK warning.
Its remaining message recommends PostgreSQL 18.
The tools, package records, protected files and resumed checks pass under the same bounded limits.
Allowing this temporary hook context requires a DAR-16 prompt decision.

Redis's post-install script creates `/run/redis` without OpenRC.
It exists after installation but disappears after checkpoint resume.
`/var/log/redis` also disappears because the guest uses temporary mounts.
The workload uses explicit temporary paths and does not test the packaged service's default startup.
No script is rerun secretly, and no service lifecycle support is added.

All seven image gates run on A and B before installation and after their checkpoints resume.
They also run on the unsafe replay and the hook-context candidate.
All six reports pass six gates and retain the known Git TLS decrypt-alert failure.
No new gate failure is accepted for a candidate.
The signed sudo negative separately requires the SUID and PATH gates to fail for the intended reason.
No sudo checkpoint is published.

The full-state replay includes package databases, account files, config files, ownership and every persistent changed path.
It records deleted paths and their preimages too, though this transaction deletes none.
The safe precondition check finds 11 mismatched paths on B.
The controlled unsafe replay then applies all 66 changed paths and proves their final bytes and basic metadata match A.
It does not implement a production applier, xattr handling, file capabilities or package-aware state merging.

## Reproduce

Use Linux x86_64, Node, Python, OpenSSL, Docker, QEMU/KVM and `debugfs`.
Install the normal repository dependencies.
If the guest helpers are absent, build them with `make guest-amd64`.
The A and stock asset directories above must exist in the local Gondolin object store.
The previous Go preparation must supply its verified ORAS 1.3.5 runtime.
`DAR16_ORAS_RUNTIME` can select that runtime directory.

Get the coordinator's VM slot before resolution, base construction, trials or e2e.
Use a fresh disk-backed directory with several GiB free.
The commands never delete an existing runtime or another invocation's files.
From the repository root:

```sh
runtime=$(mktemp -d /home/dario/Code/corb/image/build/dar16-apk.XXXXXX)
export DAR16_APK_EVIDENCE_DIR="$runtime/evidence"
python3 spike/dar-16-apk-portability/prepare.py bootstrap "$runtime"
node spike/dar-16-apk-portability/resolve.mjs "$runtime"
node spike/dar-16-apk-portability/build-base.mjs "$runtime"
node spike/dar-16-apk-portability/run.mjs "$runtime"
python3 spike/dar-16-apk-portability/oci.py "$runtime"
python3 spike/dar-16-apk-portability/inspect-bases.py "$runtime"
node --test --test-isolation=none spike/dar-16-apk-portability/plan.test.mjs
```

Preparation fetches a fresh signed snapshot, then freezes it for all transactions.
The historical versions can disappear from the live CDN.
Keep the ignored authenticated runtime inputs to repeat the exact measured snapshot.
A new snapshot or new helper binary can produce a different B build ID.
The source records actual selected versions and identities instead of pretending that a rebuild is identical.

The real HTTP handler serves only the frozen, rehashed CDN index and package paths during installation.
It rejects unexpected hosts, methods and package paths.
Verifier VMs permit only the existing gate hosts and have no installer mount.

Each VM has 1 GiB, two CPUs and a 90-second startup limit.
Commands have five-minute limits, and gate commands have 90-second limits.
The main trial has a 45-minute overall limit.
The measured run used 11 serial VMs across resolution, A/B trials, replay, sudo and the hook variant.

`DAR16_APK_EVIDENCE_DIR` keeps independent review output outside tracked evidence.
Without it, the scripts write this spike's `evidence/` directory.
Archives, extracted keys, full filesystem inventories, layouts and checkpoints stay in the ignored runtime.
Each cache identity includes the exact base assets, bundle digest and policy version.
Wrong-base resume must reject before boot, and canonical checkpoints must keep their hashes.

The main script also accepts `fixed`, `variant`, `delta`, `sudo`, `hooks` or `audit` after the runtime path.
These modes support explicit phased trials and final reporting recovery.
An existing recorded installation can resume after its checkpoint and identity are verified.
The saved result is not relabelled as a new installation.
The `audit` phase boots no VM.

The recorded run used those phases.
A later reporting change removes duplicate raw package database text and keeps its hashes and parsed identities.
The final audit also records all existing ref targets and their assets.
The coordinator independently captured the prior canonical A/stock hashes and all four refs before the experiments.

## OCI and evidence

ORAS 1.3.5 copies the artifact between two local OCI layouts.
The script verifies the ORAS binary against the previously checked official release archive.
The artifact has two signed index blobs and seven APK blobs, with recipe metadata as its config.
It has no base build ID or installed filesystem changes.
Every copied descriptor must retain its expected size and SHA-256.
No remote registry, authentication or publisher-signature flow is tested.

The artifact manifest digest is:

```text
sha256:0a2020acfdf901e5a76485a9ebfb7117ca95ac2c1c836f4570189fbad6b6df80
```

| Evidence | Contents |
| --- | --- |
| `bundle.json`, `resolution.json`, `oci.json` | Exact signed inputs, dependency plans, installer identity and OCI roundtrip |
| `base-b.json`, `base-package-controls.json` | New base, incomplete stock records and measured stale OpenSSL bytes |
| `fixed.json`, `variant.json` | Package records, native outputs, baseline and resumed gates, separate checkpoint identities |
| `*-delta.json`, `delta-replay.json` | Complete changed paths and preimages, safe rejection and consumer-state loss |
| `negative-checksum.json`, `negative-signature.json`, `negative-sudo.json` | Real rejecting checksum, RSA signature and security paths |
| `hooks.json` | Temporary transaction-only hook context, cleanup and resumed verification |
| `*-protected-*.sha256`, `events.jsonl` | Complete protected hashes, commands, timings, warnings and native behavior |
| `inputs*.json`, `source-sha256.json`, `global-baseline.json`, `result.json`, `cleanup.json`, `host-cleanup.json`, `checks.json` | Source hashes, refs, final integrity audit, host cleanup and repository checks |

The signed index marks `postgresql-common` as x86_64 while its signed `.PKGINFO` says `noarch`.
The verifier accepts this compatible noarch payload only after the same exact signed identity and checksum pass.
Other binary architectures reject.

Typecheck, source lint and both changed docs pass.
The repository passes 1,518 unit tests across 55 files and 53 serial e2e tests across 10 files.
Seven plan/preimage cases and seven reused gate-verdict cases pass.
Host process checks find no remaining experimental or e2e VMs.
All 11 recorded VM PIDs exited before the slot release.
The isolated task registry is empty.

## Decisions left for production

Choose package-input reuse with a per-base transaction, or define a stricter conditional filesystem-delta contract.
Decide how base package records become consistent with their actual files.
Decide whether root package hooks may see a temporary `apk` command.
Keep base upgrades, reinstalls and removals explicit instead of silently accepting a solver change.
Define which package effects conflict with Corb's security policy and must reject.
Service startup and temporary-directory creation need a separate lifecycle policy before such support is promised.

This finite matrix does not establish arbitrary APK, future base, cross-patch or cross-architecture portability.
