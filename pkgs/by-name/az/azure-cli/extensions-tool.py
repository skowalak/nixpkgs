#!/usr/bin/env python

import argparse
import base64
import json
import logging
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Iterable, Optional
from urllib.request import Request, urlopen

from packaging.version import Version, parse


INDEX_URL = "https://azcliextensionsync.blob.core.windows.net/index1/index.json"

logger = logging.getLogger(__name__)


@dataclass
class Ext:
    pname: str
    version: Version
    url: str
    hash: str
    description: str

def eprint(*args, **kwargs):
    logger.error(*args, **kwargs)


def get_index(cache_dir: str):
    cache_file = f"{cache_dir}/index.json"
    eprint(f"Downloading index to {cache_file}")
    os.makedirs(cache_dir, exist_ok=True)
    with open(cache_file, "wb") as f:
        req = Request(INDEX_URL)
        with urlopen(req) as resp:
            f.write(resp.read())
    with open(cache_file, "r") as f:
        return json.load(f)


def _convert_hash_digest_from_hex_to_b64_sri(s: str) -> str:
    try:
        b = bytes.fromhex(s)
    except ValueError as err:
        logger.error("not a hex value: %s", str(err))
        raise err

    return f"sha256-{base64.b64encode(b).decode("utf-8")}"

def _filter_invalid(o: Dict[str, Any]) -> bool:
    if "metadata" not in o:
        logger.warning("extension without metadata")
        return False
    metadata = o["metadata"]
    if "name" not in metadata:
        logger.warning("extension without name")
        return False
    if "version" not in metadata:
        logger.warning(f"{metadata['name']} without version")
        return False
    if "azext.minCliCoreVersion" not in metadata:
        logger.warning(f"{metadata['name']} {metadata['version']} does not have azext.minCliCoreVersion")
        return False
    if "summary" not in metadata:
        logger.info(f"{metadata['name']} {metadata['version']} without summary")
        return False
    if "downloadUrl" not in o:
        logger.warning(f"{metadata['name']} {metadata['version']} without downloadUrl")
        return False
    if "sha256Digest" not in o:
        logger.warning(f"{metadata['name']} {metadata['version']} without sha256Digest")
        return False

    return True


def _filter_compatible(o: Dict[str, Any], cli_version: Version) -> bool:
    minCliVersion = parse(o["metadata"]["azext.minCliCoreVersion"])
    return cli_version >= minCliVersion


def _transform_dict_to_obj(o: Dict[str, Any]) -> Ext:
    m = o["metadata"]
    return Ext(
        pname=m["name"],
        version=parse(m["version"]),
        url=o["downloadUrl"],
        hash=_convert_hash_digest_from_hex_to_b64_sri(o["sha256Digest"]),
        description=m["summary"]
    )

def _get_latest_version(versions: Iterable[Ext]) -> Optional[Ext]:
    logger.debug((versions))
    v = list(versions).sort(key="version", reverse=True)
    if v:
        return v[0]

    return None


def processExtension(extVersions: dict, cli_version: Version):
    extVersions = filter(_filter_invalid, extVersions)
    extVersions = filter(lambda v: _filter_compatible(v, cli_version), extVersions)
    extVersionsObj = map(_transform_dict_to_obj, extVersions)
    return _get_latest_version(extVersionsObj)


def main():
    logging.basicConfig(level=logging.DEBUG, stream=sys.stderr, format="%(message)s")
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

    i = get_index(args.cache_dir)
    assert i["formatVersion"] == "1"  # only support formatVersion 1
    extensions = i["extensions"]

    eprint(f"Filtering extensions for azure-cli version {args.cli_version}")
    cli_version = parse(args.cli_version)
    for extName, extVersions in extensions.items():
        extensions[extName] = processExtension(extVersions, cli_version)

    print(json.dumps(
        [asdict(e) for e in extensions],
        indent=2
    ))


if __name__ == "__main__":
    main()
