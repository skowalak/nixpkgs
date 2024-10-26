#!/usr/bin/env python

import argparse
import os
import json
from urllib.request import Request, urlopen
from pathlib import Path
from packaging.version import Version
import sys


INDEX_URL = "https://azcliextensionsync.blob.core.windows.net/index1/index.json"


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def getIndex(cache_dir: str):
    cache_file = f"{cache_dir}/index.json"
    eprint(f"Downloading index to {cache_file}")
    os.makedirs(cache_dir, exist_ok=True)
    with open(cache_file, "wb") as f:
        req = Request(INDEX_URL)
        with urlopen(req) as resp:
            f.write(resp.read())
    with open(cache_file, "r") as f:
        return json.load(f)

def processExtension(extVersions: dict, cli_version: str):
    latestCompatibleVersion = None
    for extVersion in extVersions:
        if "metadata" not in extVersion:
            eprint(f"WARN: extension without metadata")
            return
        metadata = extVersion["metadata"]
        if "name" not in metadata:
            eprint(f"WARN: extension without name")
            return
        if "version" not in metadata:
            eprint(f"WARN: {metadata['name']} without version")
            return
        ver = Version(metadata["version"])
        if "azext.minCliCoreVersion" not in metadata:
            eprint(f"WARN: {metadata['name']} {metadata['version']} does not have azext.minCliCoreVersion")
            return
        minCliVer = Version(metadata["azext.minCliCoreVersion"])

        if Version(cli_version) < minCliVer:
            continue

        if latestCompatibleVersion is None or ver > Version(
            latestCompatibleVersion["metadata"]["version"]
        ):
            latestCompatibleVersion = extVersion

    return latestCompatibleVersion


def toNixCompat(extVer: dict):
    nixCompat = dict()
    if "metadata" not in extVer:
        eprint(f"WARN: extension without metadata")
        return
    metadata = extVer["metadata"]
    if "name" not in metadata:
        eprint(f"WARN: extension without name")
        return
    nixCompat["pname"] = metadata["name"]
    if "version" not in metadata:
        eprint(f"WARN: {metadata['name']} without version")
        return
    nixCompat["version"] = metadata["version"]
    if "downloadUrl" not in extVer:
        eprint(f"WARN: {metadata['name']} {metadata['version']} without downloadUrl")
        return
    nixCompat["url"] = extVer["downloadUrl"]
    if "summary" in metadata:
        nixCompat["description"] = metadata["summary"]




def main():
    parser = argparse.ArgumentParser(
        prog="azure-cli.extensions-tool",
        description="Script to handle Azure CLI extensions",
    )
    parser.add_argument(
        "--cli-version", type=str, help="version of azure-cli (required)"
    )
    parser.add_argument("--extension", type=str, help="name of extension to query")
    parser.add_argument(
        "--cache-dir",
        type=str,
        help="path where to cache the extension index",
        default=os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")
        / "azure-cli-extensions-tool",
    )
    parser.add_argument(
        "--requirements",
        type=str,
        choices=["true", "false"],
        help="filter for extensions with/without requirements",
    )
    args = parser.parse_args()

    i = getIndex(args.cache_dir)
    assert i["formatVersion"] == "1"  # only support formatVersion 1
    extensions = i["extensions"]

    eprint(f"Filtering extensions for azure-cli version {args.cli_version}")
    for extName, extVersions in extensions.items():
        extensions[extName] = processExtension(extVersions, args.cli_version)

    print(json.dumps(extensions, indent=2))


if __name__ == "__main__":
    main()
