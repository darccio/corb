#!/usr/bin/env python3
"""Verify each exact pin against fresh signed indexes and CDN packages."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bootstrap", root / "fetch-apk.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
keys = Path.home() / ".cache/corb/dar-15-layers/trusted/2747a805-7a7e-5798-84ca-077fb5086311/keys"
pins = tomllib.loads((root / "pins-proposal.toml").read_text())["target"]["x86_64"]["package"]


def check_record(pin, records):
    record = next((record for record in records if record.get("P") == pin["name"] and record.get("V") == pin["version"]), None)
    if record is None:
        raise ValueError("Pinned package " + pin["name"] + "=" + pin["version"] + " is no longer on the CDN signed index. Refresh the workspace pins before rebuilding.")
    if record.get("C") != pin["apkindex-checksum"]:
        raise ValueError("Pinned APKINDEX checksum changed for " + pin["name"] + "=" + pin["version"])
    return record


with tempfile.TemporaryDirectory(prefix="dar15-pin-") as temporary:
    directory = Path(temporary)
    indexes = {}
    for repository in ["main", "community"]:
        raw = bootstrap.download("https://dl-cdn.alpinelinux.org/alpine/v3.23/" + repository + "/x86_64/APKINDEX.tar.gz", directory / "index.tar.gz")
        parts = bootstrap.members(raw)
        bootstrap.verify_signature(parts, keys, directory)
        indexes[repository] = [dict(line.split(":", 1) for line in block.splitlines() if ":" in line) for block in bootstrap.entries(parts[1][1])["APKINDEX"].decode().split("\n\n")]
    for pin in pins:
        record = check_record(pin, indexes[pin["repository"]])
        filename = pin["name"] + "-" + pin["version"] + ".apk"
        raw = bootstrap.download("https://dl-cdn.alpinelinux.org/alpine/v3.23/" + pin["repository"] + "/x86_64/" + filename, directory / "package.apk")
        parts = bootstrap.members(raw)
        checksum = "Q1" + base64.b64encode(hashlib.sha1(parts[1][0]).digest()).decode()
        if checksum != record["C"]:
            raise ValueError("Downloaded package differs from pinned APKINDEX checksum: " + filename)
        bootstrap.verify_signature(parts, keys, directory)
        fields = dict(line.split(" = ", 1) for line in bootstrap.entries(parts[1][1])[".PKGINFO"].decode().splitlines() if " = " in line)
        if fields["pkgname"] != pin["name"] or fields["pkgver"] != pin["version"]:
            raise ValueError("Package identity differs from exact pin: " + filename)
        if hashlib.sha256(parts[2][0]).hexdigest() != fields["datahash"]:
            raise ValueError("Downloaded payload differs from signed datahash: " + filename)
        print(json.dumps({"verified": filename, "bytes": len(raw), "apkindex-checksum": checksum}), flush=True)
    negatives = [dict(pins[0], version="0.0.0-dar15-missing"), dict(pins[0], **{"apkindex-checksum": "Q1invalid"})]
    for pin in negatives:
        try:
            check_record(pin, indexes[pin["repository"]])
        except ValueError as error:
            print(json.dumps({"negativeRejected": True, "message": str(error)}), flush=True)
        else:
            raise AssertionError("A changed exact pin was accepted")
print(json.dumps({"verifiedPins": len(pins), "negativeChecks": len(negatives), "localApkCacheCreated": False}), flush=True)
