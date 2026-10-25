# Conditional installed-state control

This control changes one unrelated protected config file in a private copy of base A.
The changed rootfs gives base C a different content-derived Gondolin build ID.
It preserves the producer delta's package, account, config and file preimages.
This is a controlled image variant, not a released Corb version or a production layer contract.

The script copies every verified base asset to a fresh task directory.
It rejects symlinks, hardlinks and a rootfs inode shared with the canonical base before writing anything.
It adds `/etc/corb/apk-portability-control.txt` through `debugfs` on that private rootfs only.
It recomputes all asset checksums and the build ID, then verifies and imports C without a tag.

The experiment imports the private SDK helper `computeAssetBuildId` from `dist/src/assets.js`.
Its source lines 219-234 derive the UUID from asset checksums and architecture.
The production builder calls the same helper in `dist/src/build/shared.js`.
The script first verifies that this helper reproduces A's known build ID.
This private API use is limited to experimental base construction.

Prepare C without booting a VM:

```sh
runtime=/home/dario/Code/corb/image/build/dar-16-apk-portability
node spike/dar-16-apk-portability/conditional-control.mjs "$runtime" prepare
```

Wait for the coordinator's explicit VM-slot grant before the next command:

```sh
node spike/dar-16-apk-portability/conditional-control.mjs "$runtime" run
```

The trial boots only one VM at a time, with 1 GiB and two CPUs.
It has a 20-minute overall limit and uses the existing bounded guest commands and gates.
It checks all producer preimages twice before applying the same complete delta tar and replay code.
It rejects a mismatch instead of relaxing the preconditions.
The low-level replay code still labels itself unconditional because the caller supplies the guard.
This control enables that guard before invoking it.

The script checks every postimage, C's own protected baseline and the new config marker.
It runs all three native workloads and seven image gates.
It then creates C's own checkpoint, resumes it against C and repeats those checks.
No old checkpoint is rebased.
The final audit verifies A/C assets, checkpoint hashes and unchanged refs.

Default evidence goes to `evidence/conditional-control/`.
An inherited `DAR16_APK_EVIDENCE_DIR` receives a separate `conditional-control/` subdirectory.
`DAR16_CONDITIONAL_EVIDENCE_DIR` selects an explicit separate review directory.
The script rejects a destination that already contains the primary matrix evidence.
Large runtime files stay in the existing ignored task runtime.
Existing Go and APK matrix evidence remains unchanged.

A positive result supports an installed-state delta when every affected prior path matches.
It does not prove that the Alpine branch alone gives compatibility.
The B corruption counterexample remains valid for differing touched state.
Matching written-path preimages alone does not cover arbitrary scripts' read-only inputs, kernel features, ABI or runtime initialization.
Xattrs, file capabilities, package-aware merging and a production applier remain untested.

## Measured result

The conditional replay succeeds on C, build `7ec74d62-c2c5-50cc-b69b-324a549924a8`.
Its rootfs SHA-256 is `6dc45aa6c80cdfe6a831b7cce46a658047f504b93a1ef685436dfed7e491c0da`.
All 66 producer preimages match twice before mutation.
All 66 postimages match afterward, and C's additional protected config survives.
All three native workloads pass before and after C's own checkpoint resume.

Baseline, candidate and resumed gates each pass six of seven checks.
Only the known Git TLS decrypt-alert failure remains.
The forbidden PATH names remain absent, and protected files and package records stay equal across resume.
The canonical checkpoint, A/C assets and global refs remain unchanged.
This uses two serial VMs and does not rebase an old checkpoint.

The measured trial precedes an output-only entrypoint correction.
That correction prevents an inherited matrix output directory from receiving control evidence directly.
The result keeps its original executed-source hash.
Separate metadata records the final corrected entrypoint hash and its rejection check.

Typecheck, source lint and all three changed docs pass.
All 1,518 unit tests pass across 55 files.
All 53 serial e2e tests pass across 10 files in 265.70 seconds.
Host checks confirm both control PIDs exited, with no remaining VM or test process.
The isolated task registry is empty.
