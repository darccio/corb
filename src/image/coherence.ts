import { withImageVm } from "./verify.ts";

/** Check package evidence separately from the seven image gates. */
export async function validateImagePackageCoherence(assetDir: string): Promise<void> {
  return withImageVm(assetDir, { sessionLabel: "corb-image-package-coherence" }, async (vm) => {
    const result = await vm.exec([
      "/usr/bin/node", "/usr/local/libexec/corb-package-coherence.mjs", "--validate-report",
    ], { stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(30_000) });
    if (!result.ok) {
      throw new Error(`corb image build: package coherence failed: ${result.stderr.trim() || result.stdout.trim()}`);
    }
    process.stderr.write(`corb image build: ${result.stdout.trim()}\n`);
  });
}
