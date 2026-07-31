#!/usr/bin/env python3
"""Build or verify binary fixtures, the PCAPNG trace, and kit manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
KIT_ROOT = ROOT / "conformance" / "v1"
sys.path.insert(0, str(KIT_ROOT))

from kitlib import (  # noqa: E402
    KitError,
    canonical_json,
    json_pointer,
    load_kit,
    pretty_json,
    read_json,
    resolved_cases,
    sha256_file,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build/check Komms stable-v1 conformance artifacts."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    return parser.parse_args()


def media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    return {
        ".md": "text/markdown; charset=utf-8",
        ".py": "text/x-python; charset=utf-8",
        ".json": "application/json",
        ".bin": "application/octet-stream",
        ".cbor": "application/cbor",
        ".pcapng": "application/vnd.tcpdump.pcap",
    }.get(suffix, "application/octet-stream")


def pcapng_block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * ((4 - len(body) % 4) % 4)
    length = 12 + len(body) + len(padding)
    return (
        struct.pack("<II", block_type, length)
        + body
        + padding
        + struct.pack("<I", length)
    )


def build_pcap(packets: list[bytes]) -> bytes:
    section = pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface = pcapng_block(1, struct.pack("<HHI", 147, 0, 4 * 1024 * 1024))
    output = bytearray(section + interface)
    for index, packet in enumerate(packets, start=1):
        timestamp = index * 1_000_000
        body = struct.pack(
            "<IIIII",
            0,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet),
            len(packet),
        ) + packet
        output.extend(pcapng_block(6, body))
    return bytes(output)


def expected_artifacts(cases: dict[str, dict[str, Any]]) -> dict[str, bytes]:
    definition = read_json(KIT_ROOT / "artifacts.json")
    if not isinstance(definition, dict) or set(definition) != {"fixtures", "packets"}:
        raise KitError("artifacts.json has an invalid schema")
    if not isinstance(definition["fixtures"], list) or not isinstance(
        definition["packets"], list
    ):
        raise KitError("artifacts.json fixtures and packets must be lists")
    output: dict[str, bytes] = {}

    for item in definition["fixtures"]:
        if not isinstance(item, dict) or set(item) != {"path", "case", "pointer"}:
            raise KitError("fixture definition has an invalid schema")
        path_value = item["path"]
        path = Path(path_value) if isinstance(path_value, str) else None
        if (
            path is None
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != path_value
            or not path_value.startswith("fixtures/")
            or path_value in output
        ):
            raise KitError(f"fixture definition has an unsafe path: {path_value!r}")
        if not isinstance(item["case"], str) or not isinstance(item["pointer"], str):
            raise KitError("fixture definition case and pointer must be strings")
        if item["case"] not in cases:
            raise KitError(f"fixture names an unknown case: {item['case']}")
        value = json_pointer(cases[item["case"]], item["pointer"])
        if not isinstance(value, str):
            raise KitError(f"fixture pointer is not a hex string: {path_value}")
        try:
            output[path_value] = bytes.fromhex(value)
        except ValueError as error:
            raise KitError(f"fixture is not hex: {path_value}") from error

    packet_bytes = []
    packet_index = []
    packet_names: set[str] = set()
    for index, item in enumerate(definition["packets"], start=1):
        if not isinstance(item, dict) or set(item) != {
            "name",
            "case",
            "pointer",
            "description",
        }:
            raise KitError("packet definition has an invalid schema")
        if (
            not isinstance(item["name"], str)
            or not item["name"]
            or len(item["name"]) > 96
            or item["name"] in packet_names
            or not isinstance(item["case"], str)
            or not isinstance(item["pointer"], str)
            or not isinstance(item["description"], str)
            or not item["description"]
        ):
            raise KitError("packet definition has invalid or duplicate metadata")
        packet_names.add(item["name"])
        if item["case"] not in cases:
            raise KitError(f"packet names an unknown case: {item['case']}")
        value = json_pointer(cases[item["case"]], item["pointer"])
        if not isinstance(value, str):
            raise KitError(f"packet pointer is not a hex string: {item['name']}")
        packet = bytes.fromhex(value)
        packet_bytes.append(packet)
        packet_index.append(
            {
                "packet": index,
                "name": item["name"],
                "description": item["description"],
                "captured_bytes": len(packet),
                "sha256": hashlib.sha256(packet).hexdigest(),
                "contains_production_secrets": False,
                "synthetic_vector_material_only": True,
            }
        )
    output["packets/reference-v1.pcapng"] = build_pcap(packet_bytes)
    output["packets/reference-v1.json"] = pretty_json(
        {
            "format": "komms-reference-packet-index",
            "format_version": 1,
            "link_type": 147,
            "link_type_name": "USER0",
            "profile": "komms-stable-v1",
            "packets": packet_index,
        }
    )
    return output


def manifest_bytes() -> bytes:
    files = []
    for path in sorted(KIT_ROOT.rglob("*")):
        if path.is_symlink():
            raise KitError(f"kit may not contain symlinks: {path}")
        if (
            not path.is_file()
            or path.name == "manifest.json"
            or "__pycache__" in path.parts
            or "evidence" in path.relative_to(KIT_ROOT).parts
        ):
            continue
        relative = path.relative_to(KIT_ROOT)
        files.append(
            {
                "path": relative.as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "media_type": media_type(path),
            }
        )
    return pretty_json(
        {
            "format": "komms-conformance-manifest",
            "format_version": 1,
            "profile": "komms-stable-v1",
            "kit_version": "1.0.0",
            "files": files,
        }
    )


def compare_or_write(path: Path, expected: bytes, write: bool) -> None:
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected)
        return
    if not path.is_file() or path.read_bytes() != expected:
        raise KitError(f"generated artifact drift: {path.relative_to(ROOT)}")


def main() -> None:
    args = parse_args()
    _, cases = load_kit(KIT_ROOT)
    cases = resolved_cases(cases)
    by_id = {case["id"]: case for case in cases}
    for relative, expected in expected_artifacts(by_id).items():
        compare_or_write(KIT_ROOT / relative, expected, args.write)

    # The manifest is computed last so it covers the newly checked/written
    # generated packet and fixture bytes.
    compare_or_write(KIT_ROOT / "manifest.json", manifest_bytes(), args.write)
    verb = "built" if args.write else "verified"
    print(f"{verb} stable-v1 binary fixtures, packet trace, and manifest")


if __name__ == "__main__":
    try:
        main()
    except (KitError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"kit build failed: {error}", file=sys.stderr)
        raise SystemExit(1)
