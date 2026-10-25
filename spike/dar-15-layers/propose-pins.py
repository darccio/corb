#!/usr/bin/env python3
"""Write a shareable pin-format proposal from the measured first layer."""

import hashlib
import importlib.util
import json
from pathlib import Path

root = Path(__file__).resolve().parent
runtime = root / "runtime"
spec = importlib.util.spec_from_file_location("bootstrap", root / "fetch-apk.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
keys = Path.home() / ".cache/corb/dar-15-layers/trusted/2747a805-7a7e-5798-84ca-077fb5086311/keys"


def package_records(text):
    return [dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
            for block in text.split("\n\n")]


indexes = {}
for repository in ["main", "community"]:
    if repository == "main":
        raw = (Path.home() / ".cache/corb/dar-15-layers/APKINDEX.tar.gz").read_bytes()
    else:
        raw = bootstrap.download(
            "https://dl-cdn.alpinelinux.org/alpine/v3.23/community/x86_64/APKINDEX.tar.gz",
            runtime / "APKINDEX-community.tar.gz",
        )
    parts = bootstrap.members(raw)
    bootstrap.verify_signature(parts, keys, runtime)
    indexes[repository] = package_records(bootstrap.entries(parts[1][1])["APKINDEX"].decode())

rows = [json.loads(line) for line in (root / "evidence-05-original-install.log").read_text().splitlines() if line.startswith("{")]
before = {record["P"]: record for record in package_records(next(row["stdout"] for row in rows if row.get("label") == "base-db")) if "P" in record}
after = package_records(next(row["stdout"] for row in rows if row.get("label") == "installed-after"))
pins = []
for package in after:
    name = package.get("P")
    if not name or (name in before and before[name]["V"] == package["V"] and before[name]["C"] == package["C"]):
        continue
    repository = next((repo for repo, records in indexes.items() if any(
        record.get("P") == name and record.get("V") == package["V"] and record.get("C") == package["C"]
        for record in records)), None)
    if repository is None:
        raise ValueError("Measured pin no longer matches a signed repository index: " + name)
    pins.append({"name": name, "version": package["V"], "apkindex-checksum": package["C"], "repository": repository})

definition = {"build-hosts": ["dl-cdn.alpinelinux.org"], "packages": ["go", "postgresql16-client"]}
fingerprint = hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
lines = [
    "# Format proposal for review.",
    "# This example names the stock base used in the first experiment.",
    "version = 1", "", "[target.x86_64]",
    'base = "corb:0.1.0-x86_64-171874b9"',
    "definition-sha256 = " + json.dumps(fingerprint),
]
for pin in sorted(pins, key=lambda pin: pin["name"]):
    lines.extend(["", "[[target.x86_64.package]]"])
    lines.extend(key + " = " + json.dumps(value) for key, value in pin.items())
(root / "pins-proposal.toml").write_text("\n".join(lines) + "\n")
print(json.dumps({"definition": definition, "definitionSha256": fingerprint, "pinCount": len(pins), "pins": pins}, indent=2))
