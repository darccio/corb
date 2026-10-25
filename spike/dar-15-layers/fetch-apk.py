#!/usr/bin/env python3
"""Fetch apk.static through a signed index and verify its payload."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import urllib.request
import zlib


def members(raw):
    result = []
    while raw:
        decoder = zlib.decompressobj(31)
        content = decoder.decompress(raw)
        if not decoder.eof:
            raise ValueError("Incomplete gzip member")
        size = len(raw) - len(decoder.unused_data)
        result.append((raw[:size], content))
        raw = decoder.unused_data
    return result


def entries(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        return {
            item.name: archive.extractfile(item).read()
            for item in archive
            if item.isfile()
        }


def verify_signature(parts, keys, directory):
    signatures = entries(parts[0][1])
    for name, signature in signatures.items():
        if not name.startswith(".SIGN."):
            continue
        _, _, algorithm, keyname = name.split(".", 3)
        digest = {"RSA": "sha1", "RSA256": "sha256", "RSA512": "sha512"}[algorithm]
        key = keys / keyname
        if not key.is_file():
            continue
        signature_path = directory / "signature.bin"
        signed_path = directory / "signed.gz"
        signature_path.write_bytes(signature)
        signed_path.write_bytes(parts[1][0])
        subprocess.run(
            ["openssl", "dgst", "-" + digest, "-verify", str(key),
             "-signature", str(signature_path), str(signed_path)], check=True
        )
        return {"key": keyname, "digest": digest}
    raise ValueError("No signature matches a trusted base-image key")


def download(url, destination):
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with urllib.request.urlopen(request, timeout=120) as response:
        content = response.read()
    destination.write_bytes(content)
    print(json.dumps({"download": url, "bytes": len(content)}), flush=True)
    return content


def main():
    image = Path(sys.argv[1]).resolve()
    cache = Path(os.environ.get("CORB_CACHE_DIR", Path.home() / ".cache/corb")) / "dar-15-layers"
    cache.mkdir(parents=True, exist_ok=True)
    trusted = cache / "trusted" / image.name
    trusted.mkdir(parents=True, exist_ok=True)
    keys = trusted / "keys"
    if not keys.exists():
        subprocess.run(
            ["/usr/sbin/debugfs", "-R", "rdump /etc/apk/keys " + str(trusted),
             str(image / "rootfs.ext4")], check=True
        )
    repository = "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64"
    index_path = cache / "APKINDEX.tar.gz"
    index_raw = download(repository + "/APKINDEX.tar.gz", index_path)
    index_parts = members(index_raw)
    index_signature = verify_signature(index_parts, keys, cache)
    index = entries(index_parts[1][1])["APKINDEX"].decode()
    records = []
    for block in index.split("\n\n"):
        records.append(dict(line.split(":", 1) for line in block.splitlines() if ":" in line))
    package = next(record for record in records if record.get("P") == "apk-tools-static")
    apk_path = cache / (package["P"] + "-" + package["V"] + ".apk")
    apk_raw = download(repository + "/" + apk_path.name, apk_path)
    apk_parts = members(apk_raw)
    checksum = "Q1" + base64.b64encode(hashlib.sha1(apk_parts[1][0]).digest()).decode()
    if checksum != package["C"]:
        raise ValueError("Package control checksum differs from signed APKINDEX")
    package_signature = verify_signature(apk_parts, keys, cache)
    pkginfo = entries(apk_parts[1][1])[".PKGINFO"].decode()
    fields = dict(line.split(" = ", 1) for line in pkginfo.splitlines() if " = " in line)
    payload_hash = hashlib.sha256(apk_parts[2][0]).hexdigest()
    if payload_hash != fields["datahash"]:
        raise ValueError("Package payload differs from signed control datahash")
    binary = entries(apk_parts[2][1])["sbin/apk.static"]
    binary_dir = cache / "bin"
    binary_dir.mkdir(exist_ok=True)
    binary_path = binary_dir / "apk.static"
    binary_path.write_bytes(binary)
    binary_path.chmod(0o755)
    result = {
        "repository": repository,
        "package": package,
        "indexSignature": index_signature,
        "packageSignature": package_signature,
        "payloadSha256": payload_hash,
        "binarySha256": hashlib.sha256(binary).hexdigest(),
        "binaryDir": str(binary_dir),
    }
    (cache / "bootstrap.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
