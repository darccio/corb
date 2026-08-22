.PHONY: build test clean guest

# image targets land in M1.3 — not wired yet.

build:
	npm run build

test:
	npm test

clean:
	rm -rf dist

# Reproducible static build of the guest Go binaries (dropcap for now;
# policygate arrives in M7). CGO disabled and a stripped, buildid-less
# binary keep the image content hash stable across rebuilds on the same
# source.
guest:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) \
		go build -trimpath -ldflags="-s -w -buildid=" -o build/dropcap ./cmd/dropcap
