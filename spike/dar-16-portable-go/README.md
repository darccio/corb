# Portable Go payload trial

This spike tests one fixed Go SDK on two existing Corb bases.
It adds no production commands, schema, packages or image changes.

The shared payload is the official `go1.27.3.linux-amd64.tar.gz` archive.
Its SHA-256 is:

```text
65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
```

The producer copies that payload into each base's temporary root overlay.
The resulting checkpoints are separate local caches, each tied to its exact base.
Neither checkpoint is the shared Go artifact.

## Reproduce

Use Linux x86_64, Python 3.12 or later, Node, `readelf`, QEMU and KVM.
Install the repository's normal dependencies first.
The two existing base asset directories must be present under
`/home/dario/.cache/gondolin/images/objects/`:

- Stock: `2747a805-7a7e-5798-84ca-077fb5086311`.
- DAR-15 fixed: `e8292a0a-0a1a-52d5-959b-9ed372068d54`.

Use a fresh runtime directory on a disk with several GiB free.
From the repository root:

```sh
mkdir -p /home/dario/Code/corb/image/build
runtime=$(mktemp -d /home/dario/Code/corb/image/build/dar16-go.XXXXXX)
python3 spike/dar-16-portable-go/prepare.py --runtime "$runtime"
DAR16_EVIDENCE_DIR="$runtime/evidence" \
  node spike/dar-16-portable-go/run.mjs "$runtime"
node --test --test-isolation=none spike/dar-16-portable-go/gate-report.test.mjs
```

Get the coordinator's VM slot before running the script.
It boots one VM at a time, with 1 GiB and two CPUs.
Each startup has a 90-second limit.
Ordinary guest commands have a five-minute limit.
Each image-gate command has a 90-second limit.
The full script has a 45-minute limit.

Preparation downloads official Go release metadata, the Go archive, and ORAS 1.3.5.
It checks both release archives against their official checksums.
It copies the Go artifact between two local OCI layouts through the real ORAS CLI.
It then fetches the archive blob and checks the same digest again.
The extracted tree must match every file and mode from the authenticated archive.
Cached payloads receive the same check on later runs.

The script rejects an existing task checkpoint rather than deleting it.
Use a new runtime directory for a new full trial.
It never deletes another invocation's runtime.

`DAR16_EVIDENCE_DIR` selects the output directory.
Without it, output goes to this spike's `evidence/` directory.
Large archives, extracted SDKs, OCI layouts and checkpoints stay in the runtime.
No large runtime files belong in Git.

To finish only a failed final audit, keep the completed trial files and use:

```sh
DAR16_EVIDENCE_DIR="$runtime/evidence" \
  node spike/dar-16-portable-go/run.mjs "$runtime" --audit-only
```

That mode checks saved completed trials and current artifact hashes.
It performs the wrong-base rejection again, but boots no new VM.
The summary labels this recovery.
It is not another portability trial.

## What it checks

Both bases receive the same read-only host SDK mount.
Root copies only that SDK into `/opt/corb/go`, then removes write permissions.
The host installer and APK package manager are never used.
The payload mount is absent when the composed checkpoint resumes.

The test runs as uid 1000 through the production `dropcap` helper.
It builds a concurrent JSON summary program, checks its output, and runs three Go tests.
`GOTOOLCHAIN=local` and `CGO_ENABLED=0` keep the selected toolchain fixed.
Module downloads are disabled.
Build, module and installation caches use writable paths outside the SDK.

The fixture's caches remain in these experimental checkpoints.
The resume timings therefore include a warm build cache.

All SDK file bytes, protected Corb files and APK database records must stay equal.
The fixture can write its mounted workspace but cannot write the SDK.
All seven forbidden names must stay absent from `PATH`.
The pure Go phase permits no outbound HTTP request.

The script reads the current `image/verify.ts` and creates a runtime-only adapter.
Only its import path and the gate-array export change.
Source and adapter hashes are recorded.
It runs all seven gates on both untouched bases, both compositions and both resumes.
Any new candidate failure or unrelated baseline failure rejects the verdict.

The known baseline Git TLS decrypt-alert failure remains a readiness blocker.
Seven passing gates are accepted when the environment passes them.

The checksum negative invokes the same verifier on a one-byte archive change.
A protected destination is rejected before composition.
A stock checkpoint resumed against the fixed base must reject before boot.
Canonical checkpoint, base asset and global ref hashes must remain unchanged.

## Evidence and limits

`preparation.json` records source URLs, archive checksums, full-tree identity,
all 10 SDK executable ELF checks, and the local OCI roundtrip.
Go's other ELF files are test fixtures and are not counted as SDK executables.
The full file list, 1,701,422 bytes, stays in the ignored runtime.
Tracked evidence records its digest.

`stock.json` and `fixed.json` contain gate reports, package identities,
composition identities and checkpoint hashes.
The six `.sha256` files retain complete protected-file manifests.
`events.jsonl` records the guest commands and bounded outputs.
`result.json` and `cleanup.json` record the final audit.

The first run completed all four VM trials, then failed its cleanup assertion
because it did not await the SDK's async `listSessions()` function.
The final audit was recovered from those completed trial files.
It is labelled in `result.json` and `cleanup.json`.
The script now awaits the call and captures QEMU PIDs after lazy startup.

`host-vm-lifecycle.json` is a separate host monitor from that original run.
It observed three VM PIDs and no survivors.
It did not observe every VM's startup.

This tests copying and per-base checkpoint reuse.
It does not test direct SDK execution from a VFS mount, cgo, native libraries,
other architectures, krun, arbitrary APKs or future base versions.
Both tested bases use Alpine 3.23.0 and the same kernel.
The trial does not invent a released Corb 0.2.0 image.

OCI transport uses local image layouts only.
No remote registry, authentication flow or publisher-signature policy was tested.
The artifact contains no base build ID.
Production DAR-16 remains unimplemented and its prompt remains unapproved.
