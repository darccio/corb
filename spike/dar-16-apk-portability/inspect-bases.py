#!/usr/bin/env python3
"""Compare recorded and signed-library bytes without booting the bases."""

import json
import os
from pathlib import Path
import subprocess
import sys
import prepare

runtime = Path(sys.argv[1]).resolve()
prepared, records = prepare.verify_all(runtime)
bases = [("stock-control", "2747a805-7a7e-5798-84ca-077fb5086311"), ("fixed", prepare.BASE_ID),
         ("variant", json.loads((runtime / "base-b.json").read_text())["buildId"])]


def image_file(base, filename):
    return subprocess.run(["/usr/sbin/debugfs", "-R", "cat " + filename, str(base / "rootfs.ext4")],
                          check=True, capture_output=True, timeout=60).stdout


libraries = {}
for name, filename in [("libssl3", "usr/lib/libssl.so.3"), ("libcrypto3", "usr/lib/libcrypto.so.3")]:
    row = prepare.record_for(records, name)
    raw = (runtime / "input/packages" / (row["P"] + "-" + row["V"] + ".apk")).read_bytes()
    prepare.verify_apk(raw, row, runtime / "input/trusted/keys", runtime)
    data = prepare.BOOTSTRAP.entries(prepare.BOOTSTRAP.members(raw)[2][1])[filename]
    libraries[name] = {"filename": "/" + filename, "signedVersion": row["V"], "signedChecksum": row["C"], "sha256": prepare.sha(data)}
result = []
required = ["bash", "curl", "git", "openssh-client-default", "nodejs", "ripgrep", "jq"]
for name, build_id in bases:
    base = Path.home() / ".cache/gondolin/images/objects" / build_id
    db = image_file(base, "/lib/apk/db/installed")
    rows = [dict(line.split(":", 1) for line in block.splitlines() if ":" in line) for block in db.decode().split("\n\n") if block.strip()]
    by_name = {row["P"]: row for row in rows}
    result.append({"name": name, "buildId": build_id, "alpineRelease": image_file(base, "/etc/alpine-release").decode().strip(),
                   "databaseSha256": prepare.sha(db), "recordCount": len(rows), "missingKnownInstalledTools": [item for item in required if item not in by_name],
                   "libraries": [{"name": package, "recordedVersion": by_name[package]["V"], **row,
                                  "actualFileSha256": prepare.sha(image_file(base, row["filename"])),
                                  "matchesSignedCurrentBytes": prepare.sha(image_file(base, row["filename"])) == row["sha256"]} for package, row in libraries.items()]})
evidence = Path(os.environ.get("DAR16_APK_EVIDENCE_DIR", Path(__file__).resolve().parent / "evidence"))
prepare.write_json(evidence / "base-package-controls.json", result)
print(json.dumps(result))
