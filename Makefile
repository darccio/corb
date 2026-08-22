.PHONY: build test clean

# guest (Go) and image targets land in M1.2/M1.3 — not wired yet.

build:
	npm run build

test:
	npm test

clean:
	rm -rf dist
