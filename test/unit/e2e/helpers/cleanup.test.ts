import { expect, it } from "vitest";
import { attemptCleanup } from "../../../e2e/helpers/cleanup.ts";

it("retains every cleanup failure and still attempts later audits and receipts", async () => {
  const seen: string[] = []; const primary = Error("registry close failed"); const audit = Error("base changed");
  const failures = await attemptCleanup([
    { name: "registry", run: async () => { seen.push("registry"); throw primary; } },
    { name: "base", run: () => { seen.push("base"); throw audit; } },
    { name: "runtime", run: () => { seen.push("runtime"); } },
    { name: "receipt", run: () => { seen.push("receipt"); } },
  ]);
  expect(seen).toEqual(["registry", "base", "runtime", "receipt"]); expect(failures).toEqual([{ name: "registry", error: primary }, { name: "base", error: audit }]);
});
