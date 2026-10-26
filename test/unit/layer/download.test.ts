import { expect, it } from "vitest";
import { assertDownloadUrl } from "../../../src/layer/download.ts";
it.each(["http://go.dev/archive", "https://user:pass@go.dev/archive", "https://evil.dev/archive"])("rejects unauthorized download URL %s", (value) => { expect(() => assertDownloadUrl(value, ["go.dev"])).toThrow(); });
it("matches declared hosts and bounded wildcards", () => { expect(assertDownloadUrl("https://dl.google.com/go/archive", ["*.google.com"]).hostname).toBe("dl.google.com"); });

it("permits HTTPS ports on declared hosts", () => { expect(assertDownloadUrl("https://go.dev:8443/archive", ["go.dev"]).port).toBe("8443"); });
it("keeps an existing destination when exclusive creation fails", async () => {
  const fs = await import("node:fs"); const os = await import("node:os"); const path = await import("node:path");
  const { downloadInput } = await import("../../../src/layer/download.ts");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "corb-download-owned-")); const file = path.join(directory, "existing");
  try { fs.writeFileSync(file, "authoritative"); await expect(downloadInput("https://go.dev/archive", file, ["go.dev"], 100)).rejects.toThrow(); expect(fs.readFileSync(file, "utf8")).toBe("authoritative"); }
  finally { fs.rmSync(directory, { recursive: true }); }
});
