#!/usr/bin/env python

import argparse
import base64
import datetime
import json
import logging
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set, Tuple
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


class ExtByName(Ext):
    def __eq__(self, other):
        return self.pname == other.pname


def _get_cached_index(path: Path) -> Tuple[datetime.datetime, Any]:
    with open(path, "r") as f:
        data = f.read()

    j = json.loads(data)
    cache_date_str = j["cache_date"]
    if cache_date_str:
        cache_date = datetime.datetime.fromisoformat(cache_date_str)
    else:
        cache_date = datetime.datetime.min
    return cache_date, data


def _write_index_to_cache(data: Any, path: Path):
    j = json.loads(data)
    j["cache_date"] = datetime.datetime.now().isoformat()
    with open(path, "w") as f:
        json.dump(j, f)


def _get_remote_index():
    r = Request(INDEX_URL)
    with urlopen(r) as resp:
        return resp.read()


def get_extension_index(cache_dir: Path) -> Set[Ext]:
    index_file = cache_dir / "index.json"
    os.makedirs(cache_dir, exist_ok=True)

    try:
        index_cache_date, index_data = _get_cached_index(index_file)
    except FileNotFoundError:
        logger.info("index has not been cached, downloading from source")
        logger.info("creating index cache in %s", index_file)
        _write_index_to_cache(_get_remote_index(), index_file)
        return get_extension_index(cache_dir)

    if (
        index_cache_date
        and datetime.datetime.now() - index_cache_date > datetime.timedelta(days=1)
    ):
        logger.info(
            "cache is outdated (%s), refreshing",
            datetime.datetime.now() - index_cache_date,
        )
        _write_index_to_cache(_get_remote_index(), index_file)
        return get_extension_index(cache_dir)

    return json.loads(index_data)


def get_index(cache_dir: str):
    cache_file = f"{cache_dir}/index.json"
    logger.info("Downloading index to %s", cache_file)
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

    return f"sha256-{base64.b64encode(b).decode('utf-8')}"


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
        logger.warning(
            f"{metadata['name']} {metadata['version']} does not have azext.minCliCoreVersion"
        )
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


def _filter_by_name(e: Ext, ext_name: str) -> bool:
    return ext_name == e.pname


def _transform_dict_to_obj(o: Dict[str, Any]) -> Ext:
    m = o["metadata"]
    return Ext(
        pname=m["name"],
        version=parse(m["version"]),
        url=o["downloadUrl"],
        hash=_convert_hash_digest_from_hex_to_b64_sri(o["sha256Digest"]),
        description=m["summary"],
    )


def _get_latest_version(versions: Iterable[Ext]) -> Optional[Ext]:
    if not versions:
        return None

    return max(versions, key=lambda e: e.version)


def processExtension(
    extVersions: dict, cli_version: Version, ext_name: Optional[str] = None
):
    versions = filter(_filter_invalid, extVersions)
    versions = filter(lambda v: _filter_compatible(v, cli_version), versions)
    versions_obj = map(_transform_dict_to_obj, versions)
    if ext_name:
        versions_obj = filter(lambda v: _filter_by_name(v, ext_name), versions_obj)

    return _get_latest_version(versions_obj)


def _diff_sets(
    set_local: Set[Ext], set_remote: Set[Ext]
) -> Tuple[Set[Ext], Set[Ext], Set[Ext]]:
    set_local_by_name, set_remote_by_name = set_local, set_remote
    set_local_by_name.__class__ = ExtByName
    set_remote_by_name.__class__ = ExtByName
    return (
        set_local_by_name - set_remote_by_name,
        set_remote_by_name - set_local_by_name,
        set.intersection(set_local, set_remote),
    )


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
        default=Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "azure-cli-extensions-tool",
    )
    parser.add_argument(
        "--requirements",
        type=str,
        choices=["true", "false"],
        help="filter for extensions with/without requirements",
    )
    args = parser.parse_args()

    i = get_extension_index(args.cache_dir)
    assert i["formatVersion"] == "1"  # only support formatVersion 1
    extensions = i["extensions"]

    logger.info("Filtering extensions for azure-cli version %s", args.cli_version)
    cli_version = parse(args.cli_version)
    for extName, extVersions in extensions.items():
        extension = processExtension(extVersions, cli_version)
        if extension:
            extensions[extName] = asdict(extension)
        else:
            extensions[extName] = None

    print(json.dumps(extensions, indent=2, default=str))


if __name__ == "__main__":
    main()
