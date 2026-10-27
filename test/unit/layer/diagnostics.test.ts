import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { redactRegistryDiagnostics, RegistryDiagnosticRedactor } from "../../../src/layer/diagnostics.ts";

it("removes dynamic URL secrets from ORAS and official registry diagnostics", () => {
  const token = randomBytes(24).toString("hex"); const password = randomBytes(24).toString("hex");
  const text = `Put "https://user:${password}@localhost:443/v2/bases/blobs/uploads/id?_state=${token}&digest=sha256:abc": EOF\nhttp.request.uri="/v2/bases/blobs/uploads/id?_state=${token}"\n127.0.0.1 - - [date] "PUT /v2/bases/blobs/uploads/id?_state=${token} HTTP/1.1" 201\n`;
  const safe = redactRegistryDiagnostics(text);
  expect(safe.includes(token)).toBe(false); expect(safe.includes(password)).toBe(false); expect(safe).toContain("https://localhost:443/v2/bases/blobs/uploads/id?[REDACTED]"); expect(safe).toContain("HTTP/1.1\" 201");
});
it("scrubs split and oversized tokens before output tails can discard their URL prefix", () => {
  const marker = randomBytes(24).toString("hex"); const redactor = new RegistryDiagnosticRedactor();
  const input = `before https://user:${marker}@localhost/v2/object?_state=${marker}${"x".repeat(80_000)}${marker}\nafter /v2/object?_state=${marker}`;
  let safe = "";
  for (let offset = 0; offset < input.length; offset += 7) safe += redactor.write(input.slice(offset, offset + 7));
  safe += redactor.flush(); expect(safe.includes(marker)).toBe(false); expect(safe.length).toBeLessThan(200); expect(safe).toContain("after /v2/object?[REDACTED]");
});
it("fails closed when captured output ends inside URL userinfo", () => {
  const marker = randomBytes(24).toString("hex");
  expect(redactRegistryDiagnostics(`EOF https://user:${marker}`).includes(marker)).toBe(false);
  expect(redactRegistryDiagnostics(`EOF https://${marker}`).includes(marker)).toBe(false);
  expect(redactRegistryDiagnostics(`redirect //user:${marker}@localhost/v2`).includes(marker)).toBe(false);
});
