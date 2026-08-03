#!/usr/bin/env python3
"""Generate or check committed answers using one declared adapter."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
KIT_ROOT = ROOT / "conformance" / "v1"
sys.path.insert(0, str(KIT_ROOT))

from kitlib import (  # noqa: E402
    KitError,
    canonical_json,
    load_kit,
    parse_json_bytes,
    pretty_json,
    read_json,
    resolve_value,
    response_without_id,
    run_bounded_process,
)


MAX_ADAPTER_OUTPUT_BYTES = 64 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate/check Komms stable-v1 vector answers."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument(
        "--adapter",
        type=Path,
        default=ROOT / "target" / "debug" / "kult-conformance",
    )
    return parser.parse_args()


def run_adapter(adapter: Path, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payload = b"".join(canonical_json(request) for request in requests)
    output = run_bounded_process(
        adapter.resolve(),
        payload,
        timeout_seconds=180,
        max_output_bytes=MAX_ADAPTER_OUTPUT_BYTES,
    )
    lines = output.splitlines()
    if len(lines) != len(requests):
        raise KitError(
            f"adapter returned {len(lines)} responses for {len(requests)} requests"
        )
    responses: list[dict[str, Any]] = []
    for request, raw in zip(requests, lines, strict=True):
        response = parse_json_bytes(raw, f"{request['id']}: adapter response")
        if not isinstance(response, dict):
            raise KitError(f"{request['id']}: adapter response must be an object")
        if response.get("id") != request["id"]:
            raise KitError(f"{request['id']}: response id mismatch")
        responses.append(response_without_id(response))
    return responses


def main() -> None:
    args = parse_args()
    metadata, cases = load_kit(KIT_ROOT)
    completed: dict[str, Any] = {}

    # Forward references are prohibited, but answers for a write have to be
    # produced incrementally because later arguments may reference them.
    if args.write:
        responses = []
        for case in cases:
            request = {
                "id": case["id"],
                "operation": case["operation"],
                "arguments": resolve_value(case["arguments"], completed),
            }
            response = run_adapter(args.adapter, [request])[0]
            responses.append(response)
            completed[case["id"]] = response
    else:
        requests = []
        for case in cases:
            if case["expected"] is None:
                raise KitError(f"case {case['id']} has no committed expected answer")
            requests.append(
                {
                    "id": case["id"],
                    "operation": case["operation"],
                    "arguments": resolve_value(case["arguments"], completed),
                }
            )
            completed[case["id"]] = case["expected"]
        responses = run_adapter(args.adapter, requests)

    mismatches = []
    for case, response in zip(cases, responses, strict=True):
        if case["expected"] != response:
            mismatches.append(case["id"])
        if args.write:
            case["expected"] = response

    if args.write:
        offset = 0
        for relative in metadata["case_files"]:
            path = KIT_ROOT / relative
            document = read_json(path)
            count = len(document["cases"])
            document["cases"] = cases[offset : offset + count]
            path.write_bytes(pretty_json(document))
            offset += count
        print(f"wrote {len(cases)} stable-v1 vector answers")
    elif mismatches:
        raise KitError("committed vector drift: " + ", ".join(mismatches))
    else:
        print(f"{len(cases)} committed stable-v1 vector answers match the adapter")


if __name__ == "__main__":
    try:
        main()
    except KitError as error:
        print(f"vector update failed: {error}", file=sys.stderr)
        raise SystemExit(1)
