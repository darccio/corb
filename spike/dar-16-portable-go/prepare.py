#!/usr/bin/env python3
"""Prepare a fixed SDK and a local OCI roundtrip for the DAR-16 experiment."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

VERSION = "go1.27.3"
ARCHIVE = VERSION + ".linux-amd64.tar.gz"
EXPECTED = "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
METADATA_URL = "https://go.dev/dl/?mode=json&include=all"
DOWNLOAD_URL = "https://go.dev/dl/" + ARCHIVE
ORAS_VERSION = "1.3.5"


def digest(filename):
    with open(filename, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_archive(filename, expected, size):
    actual = digest(filename)
    if actual != expected or filename.stat().st_size != size:
        raise ValueError("SDK archive checksum or size mismatch")
    return actual


def download(url, filename):
    temporary = filename.with_suffix(filename.suffix + ".part")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, open(temporary, "wb") as target:
            shutil.copyfileobj(response, target)
        temporary.replace(filename)
    finally:
        temporary.unlink(missing_ok=True)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_json(filename, value):
    filename.write_text(json.dumps(value, indent=2) + "\n")


def tree_manifest(directory):
    rows = []
    for item in sorted(directory.rglob("*"), key=lambda value: value.relative_to(directory).as_posix()):
        relative = item.relative_to(directory).as_posix()
        if item.is_symlink() or not (item.is_dir() or item.is_file()):
            raise ValueError("unsupported SDK tree entry: " + relative)
        mode = oct(item.stat().st_mode & 0o777)
        rows.append(("d" if item.is_dir() else digest(item)) + " " + mode + " " + relative)
    return "\n".join(rows) + "\n"


def authenticated_tree_manifest(archive):
    rows = {}
    with tarfile.open(archive) as packed:
        for member in packed.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != "go" or ".." in parts or member.name.startswith("/"):
                raise ValueError("unsafe SDK archive path")
            if not (member.isfile() or member.isdir()):
                raise ValueError("unsupported SDK archive entry")
            name = Path(member.name).as_posix()
            if name in rows:
                raise ValueError("duplicate SDK archive entry")
            value = "d" if member.isdir() else hashlib.file_digest(packed.extractfile(member), "sha256").hexdigest()
            rows[name] = value + " " + oct(member.mode & 0o777 & ~0o222) + " " + name
    return "\n".join(rows[name] for name in sorted(rows)) + "\n"


def blob(layout, data, media_type):
    sha = hashlib.sha256(data).hexdigest()
    (layout / "blobs" / "sha256" / sha).write_bytes(data)
    return {"mediaType": media_type, "digest": "sha256:" + sha, "size": len(data)}


def prepare(runtime):
    runtime.mkdir(parents=True, exist_ok=True)
    evidence = runtime / "prepare.json"
    archive = runtime / ARCHIVE
    with urllib.request.urlopen(METADATA_URL, timeout=60) as response:
        releases = json.load(response)
    metadata = next(item for release in releases if release["version"] == VERSION
                    for item in release["files"] if item["filename"] == ARCHIVE)
    if metadata["sha256"] != EXPECTED:
        raise ValueError("official metadata differs from the fixed expected SDK digest")
    if not archive.exists():
        download(DOWNLOAD_URL, archive)
    verify_archive(archive, EXPECTED, metadata["size"])

    oras_dir = runtime / "oras"
    oras_dir.mkdir(exist_ok=True)
    oras_archive = runtime / ("oras_" + ORAS_VERSION + "_linux_amd64.tar.gz")
    oras_checksums = runtime / "oras-checksums.txt"
    release_url = "https://github.com/oras-project/oras/releases/download/v" + ORAS_VERSION + "/"
    download(release_url + "oras_" + ORAS_VERSION + "_checksums.txt", oras_checksums)
    expected_oras = next(line.split()[0] for line in oras_checksums.read_text().splitlines()
                         if line.split()[-1] == oras_archive.name)
    if not oras_archive.exists():
        download(release_url + oras_archive.name, oras_archive)
    if digest(oras_archive) != expected_oras:
        raise ValueError("ORAS archive checksum mismatch")
    with tarfile.open(oras_archive) as packed:
        member = packed.getmember("oras")
        if not member.isfile():
            raise ValueError("ORAS executable is not a regular file")
        (oras_dir / "oras").write_bytes(packed.extractfile(member).read())
        (oras_dir / "oras").chmod(0o755)
    oras = oras_dir / "oras"
    version_output = subprocess.check_output([oras, "version"], text=True, timeout=15)
    if not any(line.split(":", 1)[0] == "Version" and line.split(":", 1)[1].strip() == ORAS_VERSION
               for line in version_output.splitlines()):
        raise ValueError("unexpected ORAS version")

    layout = runtime / "oci-source"
    (layout / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)
    write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
    config = blob(layout, canonical({"version": 1, "go": VERSION, "os": "linux", "arch": "amd64",
                                    "destination": "/opt/corb/go", "cgo": False}),
                  "application/vnd.corb.spike.go.config.v1+json")
    archive_blob = layout / "blobs" / "sha256" / EXPECTED
    shutil.copyfile(archive, archive_blob)
    descriptor = {"mediaType": "application/vnd.corb.spike.go.sdk.v1.tar+gzip",
                  "digest": "sha256:" + EXPECTED, "size": archive.stat().st_size,
                  "annotations": {"org.opencontainers.image.title": "go.tar.gz"}}
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.corb.spike.go.v1", "config": config, "layers": [descriptor]}
    root = blob(layout, canonical(manifest), "application/vnd.oci.image.manifest.v1+json")
    root["annotations"] = {"org.opencontainers.image.ref.name": "go-sdk"}
    write_json(layout / "index.json", {"schemaVersion": 2, "manifests": [root]})
    roundtrip = runtime / "oci-roundtrip"
    copied = subprocess.run([oras, "cp", "--from-oci-layout", str(layout) + ":go-sdk",
                             "--to-oci-layout", str(roundtrip) + ":go-sdk"],
                            text=True, capture_output=True, check=True, timeout=120)
    fetched = runtime / "roundtrip.tar.gz"
    subprocess.run([oras, "blob", "fetch", "--oci-layout", str(roundtrip) + "@sha256:" + EXPECTED,
                    "--output", str(fetched)], text=True, capture_output=True, check=True, timeout=120)
    copied_manifest = roundtrip / "blobs" / "sha256" / root["digest"].split(":")[1]
    if digest(fetched) != EXPECTED or copied_manifest.read_bytes() != canonical(manifest):
        raise ValueError("OCI roundtrip changed artifact bytes")

    payload = runtime / "payload"
    if not payload.exists():
        payload.mkdir()
        with tarfile.open(fetched) as packed:
            for member in packed.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != "go" or ".." in parts or member.name.startswith("/"):
                    raise ValueError("unsafe SDK archive path")
                if not (member.isfile() or member.isdir()):
                    raise ValueError("unsupported SDK archive entry")
            packed.extractall(payload, filter="data")
        for item in sorted(payload.rglob("*"), reverse=True):
            item.chmod(item.stat().st_mode & 0o777 & ~0o222)
        payload.chmod(0o555)
    manifest_text = tree_manifest(payload)
    expected_manifest = authenticated_tree_manifest(archive)
    if manifest_text != expected_manifest:
        raise ValueError("cached SDK tree differs from the authenticated archive")
    (runtime / "payload.sha256").write_text(manifest_text)
    file_rows = [line.split(" ", 2)[0] + "  " + line.split(" ", 2)[2]
                 for line in manifest_text.splitlines() if not line.startswith("d ")]
    files_text = "\n".join(file_rows) + "\n"
    (runtime / "payload-files.sha256").write_text(files_text)
    elf = []
    fixture_elf_count = 0
    for item in sorted((payload / "go").rglob("*")):
        if item.is_file():
            with item.open("rb") as stream:
                magic = stream.read(4)
            if magic == b"\x7fELF":
                relative = item.relative_to(payload).as_posix()
                if not (relative.startswith("go/bin/") or relative.startswith("go/pkg/tool/")):
                    fixture_elf_count += 1
                    continue
                headers = subprocess.check_output(["readelf", "-l", "-d", item], text=True, timeout=15)
                if "INTERP" in headers or "(NEEDED)" in headers:
                    raise ValueError("SDK ELF has external loader/library requirements: " + str(item))
                elf.append({"path": relative, "sha256": digest(item),
                            "interpreter": None, "needed": []})
    tampered = runtime / "tampered.tar.gz"
    shutil.copyfile(archive, tampered)
    with tampered.open("r+b") as stream:
        stream.seek(-1, os.SEEK_END)
        value = stream.read(1)
        stream.seek(-1, os.SEEK_END)
        stream.write(bytes([value[0] ^ 1]))
    negative_digest = digest(tampered)
    try:
        verify_archive(tampered, EXPECTED, metadata["size"])
    except ValueError as error:
        negative_error = str(error)
    else:
        raise ValueError("tampered archive was not rejected by the verifier")
    finally:
        tampered.unlink()
    result = {"go": VERSION, "metadataUrl": METADATA_URL, "sourceUrl": DOWNLOAD_URL,
              "release": metadata, "actualArchiveSha256": digest(archive),
              "treeSha256": hashlib.sha256(manifest_text.encode()).hexdigest(),
              "filesSha256": hashlib.sha256(files_text.encode()).hexdigest(),
              "treeEntries": len(manifest_text.splitlines()), "fileCount": len(file_rows), "elf": elf,
              "nonToolElfFixtureCount": fixture_elf_count,
              "oras": {"version": version_output, "sourceUrl": release_url + oras_archive.name,
                       "expectedArchiveSha256": expected_oras, "actualArchiveSha256": digest(oras_archive)},
              "oci": {"manifestDigest": root["digest"], "roundtripArchiveSha256": digest(fetched),
                      "baseBuildIdPresent": False, "remoteRegistryTested": False,
                      "copyOutput": copied.stdout},
              "negative": {"tamperedArchiveSha256": negative_digest, "expectedSha256": EXPECTED,
                           "verifierError": negative_error, "rejectedBeforeVm": True}}
    write_json(evidence, result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.runtime.resolve())
