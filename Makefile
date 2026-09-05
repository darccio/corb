.PHONY: build test clean guest guest-amd64 guest-arm64 e2e

# image targets land in M1.3 — not wired yet.

build:
	npm run build

test:
	npm test

clean:
	rm -rf dist

# Reproducible static build of the guest Go binaries: dropcap and policygate
# (M7). CGO disabled and a stripped, buildid-less binary keep the image
# content hash stable across rebuilds on the same source. Output now lands
# under an arch-suffixed guest/build/<GOARCH>/ so this native build and the
# explicit cross-compiles below it (guest-amd64, guest-arm64) can coexist on
# disk; image/corb-image.json's postBuild.copy expects exactly this layout.
guest:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) \
		go build -trimpath -ldflags="-s -w -buildid=" -o build/$$(go env GOARCH)/dropcap ./cmd/dropcap
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) \
		go build -trimpath -ldflags="-s -w -buildid=" -o build/$$(go env GOARCH)/policygate ./cmd/policygate

# Plain cross-compiles into guest/build/<GOARCH>/ — Go handles GOOS/GOARCH
# natively, no chroot or QEMU emulation needed for these Go-only static
# binaries. Scoped deliberately to just this Go-binary layer: the full image
# pipeline's postBuild.commands step, which chroots into the assembled
# rootfs and runs real target-arch code, is a separate, much larger,
# explicitly out-of-scope effort.
guest-amd64:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags="-s -w -buildid=" -o build/amd64/dropcap ./cmd/dropcap
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags="-s -w -buildid=" -o build/amd64/policygate ./cmd/policygate

guest-arm64:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -trimpath -ldflags="-s -w -buildid=" -o build/arm64/dropcap ./cmd/dropcap
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -trimpath -ldflags="-s -w -buildid=" -o build/arm64/policygate ./cmd/policygate

# M2.4: real end-to-end suite (test/e2e/**), boots actual VMs against a
# freshly built guest image. Chosen dependency chain, and why: `e2e` rebuilds
# the guest binary and then runs `corb image build` itself (rather than
# leaving that to a `beforeAll` inside the test file) because `corb image
# build` already runs the full `image/verify.ts` gate suite as a precondition
# of tagging (src/commands/image.ts) — a broken image then fails loudly here,
# before the workspace-mount-specific e2e suite boots its own VM, instead of
# surfacing as a confusing failure inside that suite. `corb image build`
# always retags the moving `corb:<pkgVersion>` alias to the freshest build
# regardless of whether its own content-hash tag name happens to change (see
# docs/gondolin-notes.md's `computeContentHash` note) — that moving alias is
# what `resolveRuntimeImage()` defaults to, and so what the e2e suite boots.
e2e: guest
	node src/cli.ts image build
	CORB_E2E=1 npm run test:e2e
