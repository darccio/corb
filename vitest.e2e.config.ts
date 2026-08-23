// M2.4: separate vitest config for `test/e2e/**` — real VM boots, gated
// behind `CORB_E2E=1` (checked inside the test file itself, so a bare
// `vitest run --config vitest.e2e.config.ts` without the env var fails
// fast and clearly rather than trying to boot anything). Kept out of
// `vitest.config.ts`'s `include` entirely (that file only ever matches
// `test/unit/**/*.test.ts`) so plain `npm test` can never accidentally
// boot a VM — this config is only reached via `npm run test:e2e` / `make
// e2e`.
//
// `fileParallelism: false` matches the plan's "serial" requirement for the
// e2e suite (docs/spike-results.md's own conventions for this space): each
// e2e file boots at least one real QEMU VM, and running multiple such boots
// concurrently on the same machine is a resource-contention risk this suite
// deliberately avoids rather than tunes around. 180s matches the plan's own
// stated e2e timeout — a real VM boot plus several `vm.exec` round-trips is
// legitimately slow compared to the unit suite.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/e2e/**/*.e2e.ts"],
    fileParallelism: false,
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
