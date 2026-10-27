import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import { RegistryMarkers } from "../../../e2e/helpers/registry-markers.ts";
import { cleanVmOptions, VM_MARKER_LIMIT } from "../../../e2e/helpers/vm-options.ts";
import { redactRegistryDiagnostics } from "../../../../src/layer/diagnostics.ts";

it("privately retains dynamic upload-state markers for diagnostics and later VM option checks", () => {
  const plan = new RegistryMarkers(["fixture-password"]);
  for (let index = 0; index < 60; index++) plan.location(`/v2/bases/blobs/uploads/id?_state=${randomBytes(100).toString("hex")}`);
  expect(plan.values.length).toBe(61); plan.assertValid();
  const marker = plan.values.at(-1)!;
  expect(cleanVmOptions({ env: { injected: marker } }, plan.values)).toBe(false);
  expect(cleanVmOptions({ env: { safe: "value" } }, plan.values)).toBe(true);
  expect(redactRegistryDiagnostics(`http.request.uri="/v2/bases/blobs/uploads/id?_state=${marker}"`).includes(marker)).toBe(false);
});
it("fails closed on an oversized marker plan and remembers the failure", () => {
  const plan = new RegistryMarkers([]);
  for (let index = 0; index < VM_MARKER_LIMIT; index++) plan.location(`/v2/?_state=owned-${index}`);
  expect(() => plan.location("/v2/?_state=overflow")).toThrow("marker plan"); expect(() => plan.assertValid()).toThrow("marker plan");
  expect(() => cleanVmOptions({}, [...plan.values, "overflow"])).toThrow("marker plan");
  const bytes = new RegistryMarkers([]);
  expect(() => { for (let index = 0; index < 20; index++) bytes.location(`/v2/?_state=${index}${"x".repeat(4000)}`); }).toThrow("marker plan");
});
