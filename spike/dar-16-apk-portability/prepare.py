#!/usr/bin/env python3
"""Verify frozen signed APK inputs for the bounded portability trial."""

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import io
import urllib.request
import zlib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("dar15_bootstrap", HERE.parent / "dar-15-layers/fetch-apk.py")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)
BASE_ID = "e8292a0a-0a1a-52d5-959b-9ed372068d54"
BASE = Path.home() / ".cache/gondolin/images/objects" / BASE_ID
CDN = "https://dl-cdn.alpinelinux.org/alpine/v3.23/"
REQUESTED = ["tree", "postgresql16-client", "redis"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_json(filename, value):
    filename.write_text(json.dumps(value, indent=2) + "\n")


def download(url, target, expected_size=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept-Encoding": "identity"}), timeout=120) as response:
        data = response.read((expected_size + 1) if expected_size is not None else 8 * 1024 * 1024)
    if expected_size is not None and len(data) != expected_size:
        raise ValueError("download size differs from signed index")
    target.write_bytes(data)
    return data


def read_records(raw, keys, directory):
    parts = BOOTSTRAP.members(raw)
    signature = BOOTSTRAP.verify_signature(parts, keys, directory)
    text = BOOTSTRAP.entries(parts[1][1])["APKINDEX"].decode()
    records = [dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
               for block in text.split("\n\n") if block.strip()]
    return records, signature


def verify_apk(raw, record, keys, directory):
    if len(raw) != int(record["S"]):
        raise ValueError("APK size differs from signed index")
    parts = BOOTSTRAP.members(raw)
    if len(parts) != 3:
        raise ValueError("only the observed signed v2 APK format is supported")
    checksum = "Q1" + base64.b64encode(hashlib.sha1(parts[1][0]).digest()).decode()
    if checksum != record["C"]:
        raise ValueError("APK control checksum differs from signed index")
    signature = BOOTSTRAP.verify_signature(parts, keys, directory)
    control = BOOTSTRAP.entries(parts[1][1])
    fields = dict(line.split(" = ", 1) for line in control[".PKGINFO"].decode().splitlines() if " = " in line)
    if fields["pkgname"] != record["P"] or fields["pkgver"] != record["V"]:
        raise ValueError("APK identity differs from signed index")
    if fields["arch"] not in ["x86_64", "noarch"] or fields["arch"] not in [record["A"], "noarch"]:
        raise ValueError("APK architecture is incompatible")
    if sha(parts[2][0]) != fields["datahash"]:
        raise ValueError("APK payload differs from signed datahash")
    scripts = {name: value.decode() for name, value in control.items() if name != ".PKGINFO"}
    return {"name": record["P"], "version": record["V"], "arch": fields["arch"], "checksum": checksum,
            **({"indexArch": record["A"]} if fields["arch"] != record["A"] else {}),
            "archiveSha256": sha(raw), "payloadSha256": fields["datahash"], "signature": signature,
            "repository": record["repository"], "dependencies": record.get("D", ""),
            "provides": record.get("p", ""), "scripts": scripts}


def keys_from_base(base, destination):
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(["/usr/sbin/debugfs", "-R", "rdump /etc/apk/keys " + str(destination),
                    str(base / "rootfs.ext4")], check=True, capture_output=True)
    return destination / "keys"


def snapshot(runtime):
    root = runtime / "input"
    keys = root / "trusted/keys"
    records = []
    indexes = []
    for repository in ["main", "community"]:
        filename = root / "indexes" / (repository + ".tar.gz")
        raw = filename.read_bytes()
        rows, signature = read_records(raw, keys, runtime)
        for record in rows:
            record["repository"] = repository
        records.extend(rows)
        indexes.append({"repository": repository, "sha256": sha(raw), "signature": signature,
                        "url": CDN + repository + "/x86_64/APKINDEX.tar.gz"})
    return records, indexes


def record_for(records, name, version=None):
    found = [record for record in records if record["P"] == name and (version is None or record["V"] == version)]
    if len(found) != 1:
        raise ValueError("exact package is absent or ambiguous in snapshot: " + name + "=" + str(version))
    return found[0]


def package(runtime, record):
    filename = record["P"] + "-" + record["V"] + ".apk"
    target = runtime / "input/packages" / filename
    if not target.exists():
        download(CDN + record["repository"] + "/x86_64/" + filename, target, int(record["S"]))
    verified = verify_apk(target.read_bytes(), record, runtime / "input/trusted/keys", runtime)
    verified["filename"] = filename
    return verified


def bootstrap(runtime):
    root = runtime / "input"
    for name in ["indexes", "packages", "bin", "trusted"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    keys_from_base(BASE, root / "trusted")
    for repository in ["main", "community"]:
        download(CDN + repository + "/x86_64/APKINDEX.tar.gz", root / "indexes" / (repository + ".tar.gz"))
    records, indexes = snapshot(runtime)
    installer_record = record_for(records, "apk-tools-static")
    installer = package(runtime, installer_record)
    parts = BOOTSTRAP.members((root / "packages" / installer["filename"]).read_bytes())
    binary = BOOTSTRAP.entries(parts[2][1])["sbin/apk.static"]
    (root / "bin/apk.static").write_bytes(binary)
    (root / "bin/apk.static").chmod(0o755)
    targets = [record_for(records, name) for name in REQUESTED]
    extras = [record_for(records, name) for name in ["sudo", "libssl3", "libcrypto3"]]
    verified = [package(runtime, record) for record in targets + extras]
    state = {"branch": "v3.23", "arch": "x86_64", "indexes": indexes, "targets": targets,
             "negativeTargets": extras, "installer": installer, "installerBinarySha256": sha(binary),
             "packages": verified, "bootstrapSourceSha256": sha((HERE.parent / "dar-15-layers/fetch-apk.py").read_bytes())}
    write_json(runtime / "prepared.json", state)
    write_json(runtime / "records.json", records)
    print(json.dumps({"stage": "bootstrap", "targets": [{"name": row["P"], "version": row["V"]} for row in targets]}))


def verify_all(runtime):
    prepared = json.loads((runtime / "prepared.json").read_text())
    records, indexes = snapshot(runtime)
    if indexes != prepared["indexes"]:
        raise ValueError("signed repository snapshot changed")
    installer_record = record_for(records, prepared["installer"]["name"], prepared["installer"]["version"])
    installer = package(runtime, installer_record)
    raw = (runtime / "input/packages" / installer["filename"]).read_bytes()
    binary = BOOTSTRAP.entries(BOOTSTRAP.members(raw)[2][1])["sbin/apk.static"]
    if sha(binary) != prepared["installerBinarySha256"] or (runtime / "input/bin/apk.static").read_bytes() != binary:
        raise ValueError("cached installer differs from authenticated APK")
    for row in prepared["packages"]:
        record = record_for(records, row["name"], row["version"])
        if package(runtime, record) != row:
            raise ValueError("cached package differs from authenticated inputs")
    return prepared, records


def add_planned(runtime, plan):
    prepared, records = verify_all(runtime)
    by_name = {row["name"]: row for row in prepared["packages"]}
    for row in json.loads(plan.read_text()):
        record = record_for(records, row["name"], row["version"])
        by_name[row["name"]] = package(runtime, record)
    prepared["packages"] = sorted(by_name.values(), key=lambda row: row["name"])
    write_json(runtime / "prepared.json", prepared)
    print(json.dumps({"stage": "packages", "verified": len(prepared["packages"])}))


def negatives(runtime):
    prepared, records = verify_all(runtime)
    row = record_for(records, "tree")
    raw = (runtime / "input/packages" / (row["P"] + "-" + row["V"] + ".apk")).read_bytes()
    changed = dict(row, C="Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    try:
        verify_apk(raw, changed, runtime / "input/trusted/keys", runtime)
    except ValueError as error:
        outcome = {"rejected": True, "error": str(error), "beforeVm": True}
    else:
        raise ValueError("wrong exact C checksum was accepted")
    write_json(runtime / "negative-checksum.json", outcome)
    parts = BOOTSTRAP.members(raw)
    original = parts[0][1]
    with tarfile.open(fileobj=io.BytesIO(original)) as archive:
        entry = next(item for item in archive if item.name.startswith(".SIGN."))
    tampered = None
    for offset in range(entry.offset_data, entry.offset_data + min(entry.size, 64)):
        modified = bytearray(original)
        modified[offset] ^= 1
        for level in range(1, 10):
            compressor = zlib.compressobj(level, zlib.DEFLATED, 31)
            member = compressor.compress(modified) + compressor.flush()
            if len(member) == len(parts[0][0]):
                tampered = member + parts[1][0] + parts[2][0]
                break
        if tampered is not None: break
    if tampered is None: raise ValueError("could not construct a signature-only tamper with unchanged signed size")
    try:
        verify_apk(tampered, row, runtime / "input/trusted/keys", runtime)
    except subprocess.CalledProcessError as error:
        signature = {"rejected": True, "error": str(error), "beforeVm": True,
                     "originalSha256": sha(raw), "tamperedSha256": sha(tampered),
                     "sizeUnchanged": len(raw) == len(tampered), "controlAndPayloadUnchanged": True}
    else: raise ValueError("signature-byte tamper was accepted")
    write_json(runtime / "negative-signature.json", signature)
    print(json.dumps({"checksum": outcome, "signature": signature}))


def verify_base(runtime, base):
    manifest = json.loads((base / "manifest.json").read_text())
    if manifest["config"]["arch"] != "x86_64": raise ValueError("wrong base architecture")
    keys = keys_from_base(base, runtime / ("trusted-" + manifest["buildId"]))
    prepared, records = verify_all(runtime)
    for index in prepared["indexes"]:
        read_records((runtime / "input/indexes" / (index["repository"] + ".tar.gz")).read_bytes(), keys, runtime)
    for package in [prepared["installer"], *prepared["packages"]]:
        row = record_for(records, package["name"], package["version"])
        verify_apk((runtime / "input/packages" / package["filename"]).read_bytes(), row, keys, runtime)
    print(json.dumps({"baseBuildId": manifest["buildId"], "signedInputsVerifiedWithBaseKeys": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["bootstrap", "verify", "packages", "negative", "verify-base"])
    parser.add_argument("runtime", type=Path)
    parser.add_argument("plan", type=Path, nargs="?")
    args = parser.parse_args()
    args.runtime = args.runtime.resolve()
    args.runtime.mkdir(parents=True, exist_ok=True)
    if args.action == "bootstrap": bootstrap(args.runtime)
    elif args.action == "verify": verify_all(args.runtime)
    elif args.action == "packages": add_planned(args.runtime, args.plan)
    elif args.action == "verify-base": verify_base(args.runtime, args.plan)
    else: negatives(args.runtime)
