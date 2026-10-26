import { expect, it } from "vitest";
import { assertDownloadUrl } from "../../../src/layer/download.ts";
it.each(["http://go.dev/archive", "https://user:pass@go.dev/archive", "https://evil.dev/archive", "https://go.dev:8443/archive"])("rejects unauthorized download URL %s", (value) => { expect(() => assertDownloadUrl(value, ["go.dev"])).toThrow(); });
it("matches declared hosts and bounded wildcards", () => { expect(assertDownloadUrl("https://dl.google.com/go/archive", ["*.google.com"]).hostname).toBe("dl.google.com"); });
