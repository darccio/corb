#!/usr/bin/env python3
"""Compare recorded APK versions with the actual OpenSSL package bytes."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bootstrap", root / "fetch-apk.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
cache = Path.home() / ".cache/corb/dar-15-layers"
runtime = root / "runtime"
keys = cache / "trusted/2747a805-7a7e-5798-84ca-077fb5086311/keys"
index_parts = bootstrap.members((cache / "APKINDEX.tar.gz").read_bytes())
bootstrap.verify_signature(index_parts, keys, runtime)
index = bootstrap.entries(index_parts[1][1])["APKINDEX"].decode()
records = [dict(line.split(":", 1) for line in block.splitlines() if ":" in line) for block in index.split("\n\n")]

for name, filename in [("libcrypto3", "libcrypto.so.3"), ("libssl3", "libssl.so.3")]:
    package = next(record for record in records if record.get("P") == name)
    url = "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/" + name + "-" + package["V"] + ".apk"
    raw = bootstrap.download(url, runtime / (name + ".apk"))
    parts = bootstrap.members(raw)
    checksum = "Q1" + base64.b64encode(hashlib.sha1(parts[1][0]).digest()).decode()
    if checksum != package["C"]:
        raise ValueError("Control checksum differs from signed index")
    bootstrap.verify_signature(parts, keys, runtime)
    info = dict(line.split(" = ", 1) for line in bootstrap.entries(parts[1][1])[".PKGINFO"].decode().splitlines() if " = " in line)
    if hashlib.sha256(parts[2][0]).hexdigest() != info["datahash"]:
        raise ValueError("Payload hash differs from signed control")
    payload = bootstrap.entries(parts[2][1])["usr/lib/" + filename]
    expected = hashlib.sha256(payload).hexdigest()
    for label, build_id in [("stock", "2747a805-7a7e-5798-84ca-077fb5086311"), ("fixed", "e8292a0a-0a1a-52d5-959b-9ed372068d54")]:
        image = Path.home() / ".cache/gondolin/images/objects" / build_id / "rootfs.ext4"
        target = runtime / (label + "-" + filename)
        subprocess.run(["/usr/sbin/debugfs", "-R", "dump /usr/lib/" + filename + " " + str(target), str(image)], check=True)
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        record = {
            "image": label, "buildId": build_id, "file": "/usr/lib/" + filename,
            "signedPackage": {"name": name, "version": package["V"], "checksum": package["C"]},
            "signedPayloadFileSha256": expected, "actualFileSha256": actual, "matches": actual == expected,
        }
        print(json.dumps(record), flush=True)
