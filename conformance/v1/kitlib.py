#!/usr/bin/env python3
"""Shared, dependency-free helpers for the Komms stable-v1 conformance kit."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_CASES = 1_024
MAX_EXPANDED_HEX_BYTES = 4 * 1024 * 1024
MAX_ADAPTER_INPUT_BYTES = 64 * 1024 * 1024
MAX_ADAPTER_STDERR_BYTES = 1024 * 1024


class KitError(ValueError):
    """A deterministic conformance-kit validation failure."""


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise KitError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_json_bytes(raw: bytes, label: str) -> Any:
    """Parse bounded UTF-8 JSON and reject duplicate keys or non-finite values."""

    if len(raw) > MAX_JSON_BYTES:
        raise KitError(f"{label}: JSON exceeds {MAX_JSON_BYTES} bytes")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                KitError(f"non-finite JSON number: {value}")
            ),
        )
    except UnicodeDecodeError as error:
        raise KitError(f"{label}: JSON is not UTF-8") from error
    except json.JSONDecodeError as error:
        raise KitError(f"{label}: invalid JSON: {error}") from error


def read_json(path: Path) -> Any:
    """Read bounded UTF-8 JSON and reject duplicate object keys."""

    return parse_json_bytes(path.read_bytes(), str(path))


def canonical_json(value: Any) -> bytes:
    """Encode deterministic UTF-8 JSON without insignificant whitespace."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def pretty_json(value: Any) -> bytes:
    """Encode deterministic reviewable UTF-8 JSON."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    """Return a lowercase SHA-256 digest for one regular file."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def run_bounded_process(
    executable: Path,
    payload: bytes,
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> bytes:
    """Run one adapter without buffering unbounded child output in memory."""

    if not executable.is_file():
        raise KitError(f"adapter is not a regular file: {executable}")
    if len(payload) > MAX_ADAPTER_INPUT_BYTES:
        raise KitError("adapter input exceeds the fixed runner bound")

    with (
        tempfile.TemporaryFile() as request,
        tempfile.TemporaryFile() as output,
        tempfile.TemporaryFile() as error_output,
    ):
        request.write(payload)
        request.seek(0)
        try:
            process = subprocess.Popen(
                [os.fspath(executable)],
                stdin=request,
                stdout=output,
                stderr=error_output,
                shell=False,
            )
        except OSError as error:
            raise KitError(f"adapter could not be executed: {error}") from error

        deadline = time.monotonic() + timeout_seconds
        failure: str | None = None
        while process.poll() is None:
            if os.fstat(output.fileno()).st_size > max_output_bytes:
                failure = "adapter output exceeds the fixed runner bound"
                break
            if os.fstat(error_output.fileno()).st_size > MAX_ADAPTER_STDERR_BYTES:
                failure = "adapter stderr exceeds the fixed runner bound"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"adapter exceeded {timeout_seconds} seconds"
                break
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass

        if failure is not None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise KitError(failure)

        output_size = os.fstat(output.fileno()).st_size
        stderr_size = os.fstat(error_output.fileno()).st_size
        if output_size > max_output_bytes:
            raise KitError("adapter output exceeds the fixed runner bound")
        if stderr_size > MAX_ADAPTER_STDERR_BYTES:
            raise KitError("adapter stderr exceeds the fixed runner bound")
        if process.returncode != 0:
            error_output.seek(0)
            stderr = error_output.read(2_048).decode("utf-8", "replace")
            raise KitError(f"adapter exited {process.returncode}: {stderr}")

        output.seek(0)
        return output.read(max_output_bytes + 1)


def json_pointer(value: Any, pointer: str) -> Any:
    """Resolve a strict RFC 6901 JSON pointer."""

    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise KitError(f"JSON pointer must be empty or begin with '/': {pointer}")
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if part not in current:
                raise KitError(f"JSON pointer component does not exist: {part}")
            current = current[part]
        elif isinstance(current, list):
            if not part.isascii() or not part.isdigit():
                raise KitError(f"JSON pointer list component is not an index: {part}")
            index = int(part, 10)
            if index >= len(current):
                raise KitError(f"JSON pointer list index is out of range: {part}")
            current = current[index]
        else:
            raise KitError(f"JSON pointer descends through a scalar at: {part}")
    return current


def _hex(value: str, label: str) -> str:
    if len(value) % 2 or any(character not in "0123456789abcdef" for character in value):
        raise KitError(f"{label} must be canonical lowercase even-length hex")
    return value


def resolve_value(value: Any, completed: dict[str, Any]) -> Any:
    """Resolve the kit's compact data expressions and prior-case references."""

    if isinstance(value, list):
        return [resolve_value(item, completed) for item in value]
    if not isinstance(value, dict):
        return value

    if len(value) == 1 and "$utf8_hex" in value:
        text = value["$utf8_hex"]
        if not isinstance(text, str):
            raise KitError("$utf8_hex requires a string")
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_EXPANDED_HEX_BYTES:
            raise KitError("$utf8_hex expansion is too large")
        return encoded.hex()

    if len(value) == 1 and "$repeat_hex" in value:
        expression = value["$repeat_hex"]
        if not isinstance(expression, dict) or set(expression) != {"byte_hex", "bytes"}:
            raise KitError("$repeat_hex requires byte_hex and bytes")
        byte_hex = _hex(expression["byte_hex"], "$repeat_hex.byte_hex")
        count = expression["bytes"]
        if len(byte_hex) != 2 or not isinstance(count, int) or isinstance(count, bool):
            raise KitError("$repeat_hex requires one byte and an integer count")
        if count < 0 or count > MAX_EXPANDED_HEX_BYTES:
            raise KitError("$repeat_hex count is outside the kit bound")
        return byte_hex * count

    if len(value) == 1 and "$concat_hex" in value:
        expression = value["$concat_hex"]
        if not isinstance(expression, list):
            raise KitError("$concat_hex requires a list")
        parts = [resolve_value(item, completed) for item in expression]
        if any(not isinstance(part, str) for part in parts):
            raise KitError("$concat_hex parts must resolve to strings")
        combined = "".join(_hex(part, "$concat_hex part") for part in parts)
        if len(combined) // 2 > MAX_EXPANDED_HEX_BYTES:
            raise KitError("$concat_hex expansion is too large")
        return combined

    if len(value) == 1 and "$pad_hex" in value:
        expression = value["$pad_hex"]
        if not isinstance(expression, dict) or set(expression) != {
            "prefix_hex",
            "length",
            "byte_hex",
        }:
            raise KitError("$pad_hex requires prefix_hex, length, and byte_hex")
        prefix = resolve_value(expression["prefix_hex"], completed)
        byte_hex = _hex(expression["byte_hex"], "$pad_hex.byte_hex")
        length = expression["length"]
        if (
            not isinstance(prefix, str)
            or len(byte_hex) != 2
            or not isinstance(length, int)
            or isinstance(length, bool)
        ):
            raise KitError("$pad_hex fields have invalid types")
        prefix = _hex(prefix, "$pad_hex.prefix_hex")
        prefix_len = len(prefix) // 2
        if length < prefix_len or length > MAX_EXPANDED_HEX_BYTES:
            raise KitError("$pad_hex length is outside the kit bound")
        return prefix + byte_hex * (length - prefix_len)

    if len(value) == 1 and "$xor_hex" in value:
        expression = value["$xor_hex"]
        if not isinstance(expression, dict) or set(expression) != {
            "value",
            "offset",
            "byte_hex",
        }:
            raise KitError("$xor_hex requires value, offset, and byte_hex")
        source = resolve_value(expression["value"], completed)
        offset = expression["offset"]
        mask_hex = _hex(expression["byte_hex"], "$xor_hex.byte_hex")
        if (
            not isinstance(source, str)
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or len(mask_hex) != 2
        ):
            raise KitError("$xor_hex fields have invalid types")
        source = _hex(source, "$xor_hex.value")
        raw = bytearray.fromhex(source)
        if offset < 0 or offset >= len(raw):
            raise KitError("$xor_hex offset is out of range")
        raw[offset] ^= int(mask_hex, 16)
        return raw.hex()

    if len(value) == 1 and "$case" in value:
        expression = value["$case"]
        if not isinstance(expression, dict) or set(expression) != {"id", "pointer"}:
            raise KitError("$case requires id and pointer")
        case_id = expression["id"]
        pointer = expression["pointer"]
        if not isinstance(case_id, str) or not isinstance(pointer, str):
            raise KitError("$case id and pointer must be strings")
        if case_id not in completed:
            raise KitError(f"$case reference is forward, missing, or cyclic: {case_id}")
        return json_pointer(completed[case_id], pointer)

    return {key: resolve_value(item, completed) for key, item in value.items()}


def load_kit(kit_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load and structurally validate every ordered case document."""

    metadata = read_json(kit_root / "kit.json")
    if not isinstance(metadata, dict):
        raise KitError("kit.json must be an object")
    required = {
        "format",
        "format_version",
        "profile",
        "kit_version",
        "case_files",
    }
    if set(metadata) != required:
        raise KitError("kit.json fields do not match the version-1 schema")
    if metadata["format"] != "komms-conformance-kit":
        raise KitError("kit.json has the wrong format")
    if metadata["format_version"] != 1 or metadata["profile"] != "komms-stable-v1":
        raise KitError("kit.json names an unsupported format or profile")
    case_files = metadata["case_files"]
    if not isinstance(case_files, list) or not case_files:
        raise KitError("kit.json case_files must be a non-empty list")

    cases: list[dict[str, Any]] = []
    seen_case_files: set[str] = set()
    seen_case_ids: set[str] = set()
    for relative in case_files:
        relative_path = Path(relative) if isinstance(relative, str) else None
        if (
            not isinstance(relative, str)
            or relative_path is None
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != relative
            or not relative.startswith("cases/")
            or relative in seen_case_files
        ):
            raise KitError(f"unsafe case path: {relative!r}")
        seen_case_files.add(relative)
        document = read_json(kit_root / relative_path)
        if (
            not isinstance(document, dict)
            or set(document) != {"format_version", "profile", "cases"}
            or document["format_version"] != 1
            or document["profile"] != metadata["profile"]
            or not isinstance(document["cases"], list)
        ):
            raise KitError(f"{relative}: invalid case-document schema")
        for case in document["cases"]:
            if not isinstance(case, dict) or set(case) != {
                "id",
                "purpose",
                "operation",
                "arguments",
                "expected",
            }:
                raise KitError(f"{relative}: invalid case schema")
            case_id = case["id"]
            if (
                not isinstance(case_id, str)
                or not case_id
                or len(case_id) > 96
                or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-." for character in case_id)
                or case_id in seen_case_ids
            ):
                raise KitError(f"{relative}: invalid or duplicate case id: {case_id!r}")
            if (
                not isinstance(case["purpose"], str)
                or not case["purpose"]
                or not isinstance(case["operation"], str)
                or not case["operation"]
                or not isinstance(case["arguments"], dict)
            ):
                raise KitError(f"{relative}: case {case_id} has invalid metadata")
            seen_case_ids.add(case_id)
            cases.append(case)
            if len(cases) > MAX_CASES:
                raise KitError(f"kit exceeds the {MAX_CASES}-case limit")
    return metadata, cases


def resolved_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resolve all case arguments in declared order using committed answers."""

    completed: dict[str, Any] = {}
    resolved: list[dict[str, Any]] = []
    for case in cases:
        if case["expected"] is None:
            raise KitError(f"case {case['id']} has no committed expected result")
        resolved_case = dict(case)
        resolved_case["arguments"] = resolve_value(case["arguments"], completed)
        resolved.append(resolved_case)
        completed[case["id"]] = case["expected"]
    return resolved


def response_without_id(response: Any) -> dict[str, Any]:
    """Validate one adapter response and remove its request correlation id."""

    if not isinstance(response, dict) or "id" not in response or "ok" not in response:
        raise KitError("adapter response lacks id or ok")
    if not isinstance(response["ok"], bool):
        raise KitError("adapter response ok field is not Boolean")
    required = {"id", "ok", "result"} if response["ok"] else {"id", "ok", "error"}
    if set(response) != required:
        raise KitError("adapter response fields do not match its success state")
    if not response["ok"]:
        error = response["error"]
        if (
            not isinstance(error, dict)
            or set(error) != {"code", "message"}
            or not isinstance(error["code"], str)
            or not isinstance(error["message"], str)
        ):
            raise KitError("adapter error response has invalid fields")
    return {key: value for key, value in response.items() if key != "id"}
