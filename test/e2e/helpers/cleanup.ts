export async function attemptCleanup(steps: Array<{ name: string; run: () => unknown | Promise<unknown> }>) {
  const failures: Array<{ name: string; error: unknown }> = [];
  for (const step of steps) {
    try { await step.run(); } catch (error) { failures.push({ name: step.name, error }); }
  }
  return failures;
}
