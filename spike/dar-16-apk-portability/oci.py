#!/usr/bin/env python3
"""Copy the signed package inputs through a local OCI layout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import prepare


def blob(layout, data, media_type, title=None):
    digest = hashlib.sha256(data).hexdigest()
    (layout / "blobs/sha256" / digest).write_bytes(data)
    return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(data),
            **({"annotations": {"org.opencontainers.image.title": title}} if title else {})}


def main(runtime):
    prepared, records = prepare.verify_all(runtime)
    go_runtime = Path(os.environ.get("DAR16_ORAS_RUNTIME", "/home/dario/Code/corb/image/build/dar-16-portable-go"))
    archive = go_runtime / "oras_1.3.5_linux_amd64.tar.gz"
    metadata = json.loads((go_runtime / "prepare.json").read_text())["oras"]
    if prepare.sha(archive.read_bytes()) != metadata["expectedArchiveSha256"]:
        raise ValueError("ORAS archive differs from the official checksum recorded by the Go phase")
    executable = go_runtime / "oras/oras"
    with tarfile.open(archive) as packed:
        if packed.extractfile("oras").read() != executable.read_bytes(): raise ValueError("ORAS executable changed")
    version = subprocess.check_output([executable, "version"], text=True, timeout=15)
    if not any(line.partition(":")[0] == "Version" and line.partition(":")[2].strip() == "1.3.5" for line in version.splitlines()):
        raise ValueError("wrong ORAS version")
    layout = runtime / "oci-source"
    target = runtime / "oci-roundtrip"
    if layout.exists() or target.exists(): raise ValueError("OCI output already exists: use a fresh task runtime")
    (layout / "blobs/sha256").mkdir(parents=True)
    prepare.write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
    config = json.loads((runtime / "bundle.json").read_text())
    if "buildId" in json.dumps(config): raise ValueError("portable package bundle contains a base identity")
    descriptor = blob(layout, prepare.canonical(config), "application/vnd.corb.spike.apk.config.v1+json")
    layers = []
    files = []
    for row in prepared["indexes"]:
        files.append((runtime / "input/indexes" / (row["repository"] + ".tar.gz"), "indexes/" + row["repository"] + ".tar.gz", "application/vnd.corb.spike.apk.index.v1.tar+gzip"))
    positive = json.loads((runtime / "resolution.json").read_text())["positive"]
    names = {row["name"] for row in positive} | {prepared["installer"]["name"]}
    for row in [prepared["installer"], *prepared["packages"]]:
        if row["name"] in names:
            files.append((runtime / "input/packages" / row["filename"], "packages/" + row["filename"], "application/vnd.corb.spike.apk.package.v1"))
    for filename, title, media_type in files: layers.append(blob(layout, filename.read_bytes(), media_type, title))
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.corb.spike.apk.v1", "config": descriptor, "layers": layers}
    root = blob(layout, prepare.canonical(manifest), manifest["mediaType"])
    prepare.write_json(layout / "index.json", {"schemaVersion": 2, "manifests": [{**root, "annotations": {"org.opencontainers.image.ref.name": "apk-bundle"}}]})
    copied = subprocess.run([executable, "cp", "--from-oci-layout", str(layout) + ":apk-bundle", "--to-oci-layout", str(target) + ":apk-bundle"],
                            text=True, capture_output=True, check=True, timeout=120)
    for item in [root, descriptor, *layers]:
        digest = item["digest"].split(":")[1]
        data = (target / "blobs/sha256" / digest).read_bytes()
        if prepare.sha(data) != digest or len(data) != item["size"]: raise ValueError("OCI roundtrip bytes changed")
    result = {"orasVersion": "1.3.5", "orasArchiveSha256": metadata["expectedArchiveSha256"],
              "manifestDigest": root["digest"], "layerCount": len(layers), "allDescriptorBytesVerified": True,
              "baseBuildIdPresent": False, "remoteRegistryTested": False, "copyOutput": copied.stdout}
    prepare.write_json(runtime / "oci.json", result)
    evidence = Path(os.environ.get("DAR16_APK_EVIDENCE_DIR", Path(__file__).resolve().parent / "evidence"))
    prepare.write_json(evidence / "oci.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime", type=Path)
    main(parser.parse_args().runtime.resolve())
