const names = ["user", "privilege-drop", "suid", "removals", "ca-trust", "git-gh-shimmed", "pi"];

function knownGitFailure(gate) {
  return gate.name === "ca-trust" && /^git: ls-remote over https to github\.com failed/.test(gate.detail)
    && /curl 35/.test(gate.detail) && /decrypt error/.test(gate.detail) && !gate.detail.includes(" | ");
}

function shape(report) {
  if (report.length !== names.length || new Set(report.map(gate => gate.name)).size !== names.length
      || report.some(gate => !names.includes(gate.name) || typeof gate.ok !== "boolean")) {
    throw new Error("incomplete or unexpected image gate report");
  }
}

export function assertGateReports(baseline, ...candidates) {
  shape(baseline);
  for (const gate of baseline) {
    if (!gate.ok && !knownGitFailure(gate)) throw new Error("unrelated baseline gate failure: " + gate.name);
  }
  for (const report of candidates) {
    shape(report);
    for (const gate of report) {
      if (!gate.ok && (baseline.find(item => item.name === gate.name).ok || !knownGitFailure(gate))) {
        throw new Error("new candidate gate failure: " + gate.name);
      }
    }
  }
}
