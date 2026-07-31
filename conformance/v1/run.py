#!/usr/bin/env python3
"""Validate the stable-v1 kit or run it against a JSON-lines adapter."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

from kitlib import (
    KitError,
    canonical_json,
    load_kit,
    parse_json_bytes,
    read_json,
    resolved_cases,
    response_without_id,
    run_bounded_process,
    sha256_file,
)


KIT_ROOT = Path(__file__).resolve().parent
MAX_MANIFEST_FILES = 512
MAX_MANIFEST_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ADAPTER_OUTPUT_BYTES = 64 * 1024 * 1024
ADAPTER_TIMEOUT_SECONDS = 180


def verify_manifest() -> dict[str, Any]:
    manifest_path = KIT_ROOT / "manifest.json"
    manifest = read_json(manifest_path)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"format", "format_version", "profile", "kit_version", "files"}
        or manifest["format"] != "komms-conformance-manifest"
        or manifest["format_version"] != 1
        or manifest["profile"] != "komms-stable-v1"
        or not isinstance(manifest["files"], list)
    ):
        raise KitError("manifest.json does not match the version-1 schema")
    if len(manifest["files"]) > MAX_MANIFEST_FILES:
        raise KitError("manifest file count exceeds the fixed kit bound")

    total = 0
    seen: set[str] = set()
    for entry in manifest["files"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "bytes", "sha256", "media_type"}
            or not isinstance(entry["path"], str)
            or not isinstance(entry["bytes"], int)
            or isinstance(entry["bytes"], bool)
            or not isinstance(entry["sha256"], str)
            or not isinstance(entry["media_type"], str)
        ):
            raise KitError("manifest entry does not match the version-1 schema")
        relative = Path(entry["path"])
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != entry["path"]
            or entry["path"] in seen
            or entry["path"] == "manifest.json"
        ):
            raise KitError(f"manifest contains an unsafe or duplicate path: {entry['path']!r}")
        path = KIT_ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise KitError(f"manifest path is missing, non-regular, or a symlink: {entry['path']}")
        size = path.stat().st_size
        if size != entry["bytes"] or sha256_file(path) != entry["sha256"]:
            raise KitError(f"manifest digest/size mismatch: {entry['path']}")
        total += size
        if total > MAX_MANIFEST_TOTAL_BYTES:
            raise KitError("manifest byte total exceeds the fixed kit bound")
        seen.add(entry["path"])

    actual: set[str] = set()
    for path in KIT_ROOT.rglob("*"):
        if path.is_symlink():
            raise KitError(f"kit may not contain symlinks: {path.relative_to(KIT_ROOT)}")
        if not path.is_file():
            continue
        relative = path.relative_to(KIT_ROOT)
        if (
            relative.as_posix() == "manifest.json"
            or "__pycache__" in relative.parts
            or "evidence" in relative.parts
        ):
            continue
        actual.add(relative.as_posix())
    if actual != seen:
        missing = sorted(actual - seen)
        stale = sorted(seen - actual)
        detail = []
        if missing:
            detail.append("unmanifested: " + ", ".join(missing))
        if stale:
            detail.append("missing: " + ", ".join(stale))
        raise KitError("manifest file-set mismatch (" + "; ".join(detail) + ")")
    return manifest


def adapter_requests(cases: list[dict[str, Any]]) -> bytes:
    chunks = []
    for case in cases:
        request = {
            "id": case["id"],
            "operation": case["operation"],
            "arguments": case["arguments"],
        }
        chunks.append(canonical_json(request))
    return b"".join(chunks)


def run_adapter(path: Path, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = run_bounded_process(
        path,
        adapter_requests(cases),
        timeout_seconds=ADAPTER_TIMEOUT_SECONDS,
        max_output_bytes=MAX_ADAPTER_OUTPUT_BYTES,
    )
    lines = output.splitlines()
    if len(lines) != len(cases):
        raise KitError(
            f"adapter returned {len(lines)} responses for {len(cases)} requests"
        )

    results = []
    for case, raw in zip(cases, lines, strict=True):
        if len(raw) > 8 * 1024 * 1024:
            raise KitError(f"case {case['id']}: response exceeds 8 MiB")
        response = parse_json_bytes(raw, f"case {case['id']} adapter response")
        if not isinstance(response, dict):
            raise KitError(f"case {case['id']}: adapter response must be an object")
        if response.get("id") != case["id"]:
            raise KitError(f"case {case['id']}: response id does not match request")
        actual = response_without_id(response)
        passed = actual == case["expected"]
        results.append(
            {
                "id": case["id"],
                "passed": passed,
                "actual": actual if not passed else None,
                "expected": case["expected"] if not passed else None,
            }
        )
    return results


def write_report(
    path: Path,
    implementation: str,
    adapter: Path,
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
) -> None:
    if not implementation.strip():
        raise KitError("--implementation is required when --report is used")
    report = {
        "format": "komms-conformance-report",
        "format_version": 1,
        "profile": "komms-stable-v1",
        "kit_version": manifest["kit_version"],
        "kit_manifest_sha256": sha256_file(KIT_ROOT / "manifest.json"),
        "implementation": implementation,
        "adapter_sha256": sha256_file(adapter),
        "executed_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "independent_execution_claimed": False,
        "case_count": len(results),
        "passed": all(result["passed"] for result in results),
        "results": [
            {"id": result["id"], "passed": result["passed"]} for result in results
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(report))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the Komms stable-v1 conformance kit."
    )
    parser.add_argument(
        "--adapter",
        type=Path,
        help="executable implementing the version-1 JSON-lines adapter contract",
    )
    parser.add_argument(
        "--implementation",
        default="",
        help="human-readable implementation label used only in a report",
    )
    parser.add_argument("--report", type=Path, help="write a bounded JSON result report")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.report is not None and args.adapter is None:
        raise KitError("--report requires --adapter")
    manifest = verify_manifest()
    _, cases = load_kit(KIT_ROOT)
    cases = resolved_cases(cases)
    if args.adapter is None:
        print(
            f"Komms stable-v1 kit {manifest['kit_version']}: "
            f"manifest and {len(cases)} cases are valid"
        )
        return

    adapter = args.adapter.resolve()
    results = run_adapter(adapter, cases)
    failures = [result for result in results if not result["passed"]]
    if args.report is not None:
        write_report(
            args.report.resolve(),
            args.implementation,
            adapter,
            manifest,
            results,
        )
    if failures:
        for failure in failures:
            print(
                f"FAIL {failure['id']}\n"
                f"  expected: {json.dumps(failure['expected'], sort_keys=True)}\n"
                f"  actual:   {json.dumps(failure['actual'], sort_keys=True)}",
                file=sys.stderr,
            )
        raise KitError(f"{len(failures)} of {len(results)} cases failed")
    print(
        f"Komms stable-v1 kit {manifest['kit_version']}: "
        f"{len(results)} adapter cases passed"
    )


if __name__ == "__main__":
    try:
        main()
    except KitError as error:
        print(f"conformance failed: {error}", file=sys.stderr)
        raise SystemExit(1)
