#!/usr/bin/env python3
"""Read the reviewed dependency lock and verify downloads before installation.

Hashes are pinned from Go's download metadata and GitHub release asset digests.
This detects later changes; it does not replace publisher signature verification.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile

MANIFEST = Path(__file__).with_name("dependencies.json")
MAX_DOWNLOAD = 512 * 1024 * 1024


def load_manifest():
    lock = json.loads(MANIFEST.read_text())
    if lock.get("schema_version") != 1:
        raise ValueError("unsupported dependency manifest version")
    for spec in lock["go"].values():
        if "@v" not in spec or "latest" in spec:
            raise ValueError("Go dependency is not version-pinned")
    for spec in lock["python"].values():
        if "==" not in spec:
            raise ValueError("Python dependency is not version-pinned")
    for source in lock["sources"].values():
        if not re.fullmatch(r"[a-f0-9]{40}", source["commit"]):
            raise ValueError("source dependency is not commit-pinned")
    for variants in lock["artifacts"].values():
        for url, digest in variants.values():
            if not url.startswith("https://") or "latest" in url or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("artifact lacks a fixed HTTPS URL and SHA-256")
    return lock


def download(url, digest, destination):
    """Never write to the requested destination until its checksum matches."""
    destination = Path(destination)
    if not url.startswith("https://") or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("download requires HTTPS and a pinned SHA-256")
    with tempfile.TemporaryDirectory(prefix="redhands-download-") as tmp:
        archive = Path(tmp) / "download"
        sha = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(url, timeout=120) as response, archive.open("wb") as out:
            if not response.geturl().startswith("https://"):
                raise ValueError("insecure download redirect")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise ValueError("download exceeds size limit")
                sha.update(chunk)
                out.write(chunk)
        if sha.hexdigest() != digest:
            raise ValueError("SHA-256 mismatch; download not installed")
        shutil.copyfile(archive, destination)


def extract_binary(archive, url, member, output):
    """Extract one known regular file, never archive paths, links or directories."""
    if url.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            choices = [i for i in z.infolist() if Path(i.filename).name == member and not i.is_dir() and not stat.S_ISLNK(i.external_attr >> 16)]
            if len(choices) != 1 or choices[0].file_size > MAX_DOWNLOAD:
                raise ValueError("archive does not contain one bounded expected executable")
            with z.open(choices[0]) as src, open(output, "wb") as dst:
                shutil.copyfileobj(src, dst)
    elif url.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as tar:
            choices = [i for i in tar.getmembers() if Path(i.name).name == member and i.isfile()]
            if len(choices) != 1 or choices[0].size > MAX_DOWNLOAD:
                raise ValueError("archive does not contain one bounded expected executable")
            with tar.extractfile(choices[0]) as src, open(output, "wb") as dst:
                shutil.copyfileobj(src, dst)
    elif url.endswith(".gz"):
        with gzip.open(archive, "rb") as src, open(output, "wb") as dst:
            size = 0
            while chunk := src.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise ValueError("expanded binary exceeds size limit")
                dst.write(chunk)
    else:
        shutil.copyfile(archive, output)


def install(lock, name, target, destination):
    try:
        url, digest = lock["artifacts"][name][target]
    except KeyError as exc:
        raise ValueError(f"no verified artifact for {name} on {target}; install manually") from exc
    filename = name + (".exe" if target.startswith("windows-") else "")
    member = ("proxy" if name == "ligolo-proxy" else name) + (".exe" if target.startswith("windows-") else "")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".redhands-install-", dir=destination) as tmp:
        archive, binary = Path(tmp) / "archive", Path(tmp) / "binary"
        download(url, digest, archive)
        extract_binary(archive, url, member, binary)
        binary.chmod(0o755)
        os.replace(binary, destination / filename)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["validate", "go", "python", "source", "fetch", "install"])
    parser.add_argument("name", nargs="?")
    parser.add_argument("--platform", default=platform.system().lower() + "-" + {"x86_64":"amd64", "amd64":"amd64", "aarch64":"arm64", "arm64":"arm64"}.get(platform.machine().lower(), platform.machine().lower()))
    parser.add_argument("--output")
    args = parser.parse_args()
    lock = load_manifest()
    if args.action == "validate":
        print("Dependency manifest valid")
    elif args.action in ("go", "python"):
        print(lock[args.action][args.name])
    elif args.action == "source":
        print(lock["sources"][args.name]["commit"])
    elif not args.output:
        parser.error("--output is required")
    elif args.action == "fetch":
        url, digest = lock["artifacts"][args.name][args.platform]
        download(url, digest, args.output)
    else:
        install(lock, args.name, args.platform, args.output)


if __name__ == "__main__":
    main()
