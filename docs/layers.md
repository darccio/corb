# Share inputs and compose a local image

A workspace layer shares signed APK inputs and complete SDK archives.
Each machine composes those inputs on its own compatible Corb base.
The resulting checkpoint belongs to that exact base and stays local.
A different base needs an explicit build or pull, even when the shared inputs stay unchanged.

## Producer

Install ORAS **1.3.5** on PATH for registry transfers. Corb checks the version and never installs it.
Choose a coherent local Corb base with `[vm].image` in personal or workspace settings.
A base must pass package coherence and all seven production image gates.
Older images without the coherence report need a new base build or a separately distributed base.

Initial composition runs only on native Linux `x86_64` with QEMU.
The recipient base must match the locked Alpine branch, even for `packages = []`.
Other valid target tables stay in the lockfile without execution.

Put the recipe in the selected workspace's `corb.toml`, outside all hosted mounts.
For example:

```toml
[image.layer]
packages = ["tree"]
build-hosts = ["dl-cdn.alpinelinux.org"]
```

Then run:

```bash
corb image pin --workspace tools
corb image layer build --workspace tools
corb image layer push registry.example/team/tools:v1 --workspace tools
```

Pin explicitly refreshes signed Alpine main/community indexes and resolves exact package identities.
It gathers dependencies without using the producer's installed database, then separately simulates the requested install on the selected base.
It authenticates every archive before caching it. Pin executes no package scripts or custom commands.
It writes the selected `corb.sum` target last and clears its old artifact binding.
Other valid architecture targets and an existing lockfile symlink stay intact.

Build uses those exact cached inputs. It runs a real signed APK transaction and copies complete SDK trees.
The solver may retain compatible providers already on the base. It cannot change existing package identities or fetch an unbundled alternative.

Corb displays runtime directories, hosts and ordered unpinned root commands before executing them.
The builder closes before a separate checkpoint verifier boots. All seven gates and composition coherence must pass.

Push needs that verified local composition, but publishes only the reusable input graph.
It writes the immutable artifact URI into the selected lock target after publication succeeds.
It starts no VM and changes no current generation pointer.
Commit the workspace definition and `corb.sum` to share them. Keep personal `trusted.json` private.
None of these image commands accepts normal-run trust.

## Recipient

Review the shared definition, pins and artifact digest, then run:

```bash
corb image layer pull --workspace tools
corb run --workspace tools --trust-config
```

Pull reads the locked digest. It verifies the complete input graph and composes on the recipient's locally selected base.
It never refreshes pins or changes `corb.sum` to fit a different base.
A complete valid current composition for the exact base is a no-op without ORAS or VM work.
A cached complete graph needs no registry or APK CDN for composition, but custom commands and strict HTTPS image gates retain their declared network needs.
Initial verification is not promised to work offline.

Normal run validates local inputs, base assets, generation metadata and checkpoint before reading credentials or creating a VM.
It refuses a changed backing path before the SDK can rebase a checkpoint.
It never fetches a registry, repins or builds implicitly. Missing state gives a build or pull hint.
Dry-run and explain need no local generation.

## SDK inputs and runtime directories

Use `packages = []` for an SDK-only recipe. Pin then skips all APK indexes and installer work.
The [payload schema](configuration.md#sdk-payloads) requires an exact HTTPS URL, digest, target architecture and dedicated destination.
Archive redirects must stay on declared `build-hosts`. A digest fixes bytes. Review of the source establishes publisher trust.

Corb rejects links, traversal, duplicates, special nodes and expansion beyond the documented bounds.
It copies the complete tree with root ownership and immutable readable modes. It preserves executable bits.
Every SDK PATH entry must remain inside its destination and preserve the security tools and forbidden-name policy.

For Go, declare the SDK `bin` directory in `path`.
Put `GOCACHE`, `GOMODCACHE`, `GOPATH` and `GOBIN` in separate writable workspace directories.
Set `GOTOOLCHAIN=local` when the locked SDK must supply the compiler.

Runtime directories name approved paths below `/run` or `/var/log`, modes and guest account names.
Corb checks the accounts and every path component again before Pi starts on each resume.
It creates or fixes only the named directory, without changing children recursively.

A mismatch fails and closes the session.
The plan launches no service. There is no startup script, supervisor or automatic packaged-service launch.
Ordered root build commands can install other toolchains, but cannot alter protected files or add/change APK identities.
Services must be stopped before checkpointing. The checkpoint caches disk bytes, not running processes.

## Separate base distribution

Base artifacts are independent of input artifacts:

```bash
corb image verify private:base
corb image push registry.example/team/base:v1 --image private:base
corb image pull registry.example/team/base@sha256:DIGEST --tag private:received
```

Replace `DIGEST` with the full printed digest.
A base push verifies the local image, preserves exact raw SDK asset bytes and prints its immutable reference.
A base pull validates the graph, asset hashes and recomputed SDK build ID before import, then repeats production verification.
An existing exact object can have different harmless manifest formatting, filenames or local build metadata.
Its normalized architecture, distro and Alpine release projection must agree with the artifact.

An inconsistent existing object is an error.
Without `--tag`, pull imports untagged and prints its build ID and directory.
With `--tag`, it updates only that requested ref after verification. SDK errors after a ref write can leave that requested ref updated. Inspect the reported state before retrying.
No implicit version alias, workspace pin or layer pointer changes occur.

`corb image ls --json` provides version-1 JSON for local SDK refs and known workspace composition records.
The SDK inventory lists refs. It does not enumerate every untagged object.
Recorded composition status is not a substitute for run's full validation.
Listing is read-only and needs neither a VM nor network.
`corb image verify [SELECTOR]` uses the existing default when omitted and never tags or repairs an image.

## Registry and local-state limits

Push destinations require an explicit registry, repository and tag.
Pull identities require an immutable digest and never resolve a tag as the expected identity.
Both transports use verified HTTPS for localhost registries too.
ORAS 1.3.5 otherwise defaults localhost to HTTP, so Corb passes explicit false-valued `plain-http` options.

Corb never enables plain HTTP or insecure TLS.
Use `--registry-config FILE` and `--ca-file FILE` when needed. Otherwise standard ORAS credentials apply.
Registry token realms, redirects and host credential helpers are trusted transport participants.
This is not guest hostname confinement or independent publisher authentication.
These host settings never enter guest inputs or shared artifact bytes.

Local state uses private directories, immutable verified cache objects and one exclusive writer lock per workspace.
A live or uncertain owner fails. Corb recovers a lock only when its recorded local owner is provably dead, never because of age.
Completed generations stay under `CORB_STATE_DIR/layers/<workspace>/<arch>/bases/<base-id>/generations/<uuid>`.

`current.json` changes last after candidate verification. Each session receives a separate temporary SDK overlay.
Changing a base creates another cache while reusing the same authenticated input bytes.
There is no automatic generation or artifact garbage collection.

Registry writes, lockfile replacement and local pointer publication cannot form one atomic transaction.
A failed late step can leave verified cache blobs, an unused completed generation or remote data.
Corb reports the completed or uncertain stage and preserves the previous authoritative file where publication has not completed.
It removes only its own temporary children. Repeated identical input pushes have the same manifest digest.

Local OCI-layout tests do not establish remote registry authentication or transfer acceptance.
DAR-21 owns that isolated HTTPS producer/recipient flow and real packaged Redis startup checks.
