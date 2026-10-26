# Production base image

`corb-image.json` defines the production base. Keep the Alpine v3.23 branch, Pi 1.4.0, agent uid/gid 1000, and existing build selection.

The SDK extracts `rootfsPackages` without an APK transaction. This recipe leaves that list empty and installs all capabilities with APK.
The real solver runs package scripts, records dependencies and providers, and upgrades the minirootfs packages.
The build reinstalls recorded packages before adding Corb files.
An explicit `openssh-client-krb5` provider preserves the original binary's Kerberos support.
The generic provider can select `openssh-client-default`, which lacks that capability.

`helpers/package-coherence.mjs` runs before overlays and hardening. It verifies signed archives with the image's trusted APK keys.
It compares every installed package's name, version, architecture, and compressed control identity.
It also compares required native library bytes and SSH bytes with those archives.
A solver simulation must find no unresolved dependencies. The report records exact archive hashes in `/etc/corb/package-coherence.json`.

The final image keeps APK records and removes both package manager executables.
Corb also removes forbidden PATH tools, moves Git and gh behind policy shims, and installs its own protected files.
These are intentional overlays. They do not imply that every package file remains unchanged.

Before import, `image build` boots the candidate and checks its package report against current records and native bytes.
It then boots the same assets for the seven gates in `verify.ts`.
`verifyVm(vm)` runs those seven gates on an existing VM and leaves closure to its caller.
`verifyImage(assetDir, options)` provides the production CA hooks, gate mount, explicit hosts, and cleanup.
Both use one gate implementation.

The host TLS adapter in `src/vm/tls.ts` prepares the SNI context before the SDK parses handshake bytes.
It fixes the measured resumed-handshake defect without changing TLS protocols, ciphers, or verification.
See the [security guide](../docs/security.md#trusted-git-https) and [dated repair evidence](../docs/repairs/2026-10-26-base.md).

The content tag covers effective config and all configured init and copy input bytes.
It identifies build inputs, not a reproducible output or an immutable repository snapshot.
Record exact asset checksums and the Gondolin build ID for local assets.

Use an explicit private tag and an isolated store for validation:

```sh
GONDOLIN_IMAGE_STORE=/path/to/task/store \
CORB_CACHE_DIR=/path/to/task/cache \
node src/cli.ts image build --tag corb-spike:dar-20-candidate
```

An explicit tag writes only that ref. The default command writes the content tag and version alias after validation succeeds.
Changing a ref preserves the object it previously selected.
