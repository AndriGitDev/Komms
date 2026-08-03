#!/usr/bin/env python3
"""Validate operator, licensing, funding, privacy, and incident records."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 2 * 1024 * 1024
ROLE_IDS = {
    "bootstrap-kad-cache",
    "pairwise-rendezvous",
    "mailbox-v2",
    "ohttp-ingress",
    "native-wake",
}
FLOW_IDS = {
    "direct-libp2p",
    "bootstrap-kad-cache",
    "pairwise-rendezvous",
    "mailbox-v2",
    "native-wake-direct",
    "native-wake-tor-private",
    "ohttp-private",
    "release-and-update",
}
TABLETOP_IDS = {
    "service-key-compromise",
    "lawful-request",
    "cross-role-correlation",
    "operator-overload-and-eol",
}
REQUIRED_DOCS = {
    "docs/46-operator-program.md": [
        "no project reference service",
        "two real external operators",
        "P1-04 remains open",
    ],
    "docs/47-license-trademark-assets.md": [
        "AGPL-3.0-only",
        "modified version",
        "commercial",
        "government",
        "not legal advice",
        "BIP-39",
        "Pavol Rusnak",
    ],
    "docs/48-funding-transparency.md": [
        "no legal entity",
        "does not infer a zero balance",
        "P1-06 therefore remains open",
    ],
    "docs/49-privacy-legal-incident-readiness.md": [
        "qualified legal counsel",
        "do not create new logging",
        "P1-07 remains open",
    ],
    "docs/50-mailbox-service-operations.md": [
        "negotiates only",
        "matched set",
        "No public or project mailbox",
        "Local tests and an image are not operator qualification",
    ],
    "docs/52-ohttp-relay-operations.md": [
        "exactly one configured Oblivious Gateway Resource",
        "never automatically retries",
        "no OHTTP gateway HPKE private key",
        "Local tests and an image are not operator qualification",
        "No non-collusion",
    ],
}


class StewardshipError(ValueError):
    """A public stewardship record violates the checked contract."""


def read_json(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size == 0
        or path.stat().st_size > MAX_JSON_BYTES
    ):
        raise StewardshipError(f"{relative}: expected a bounded regular JSON file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StewardshipError(f"{relative}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise StewardshipError(f"{relative}: top level must be an object")
    return value


def indexed(items: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise StewardshipError(f"{label}: expected a non-empty list")
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise StewardshipError(f"{label}: malformed record")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in result:
            raise StewardshipError(f"{label}: missing or duplicate id")
        result[identifier] = item
    return result


def validate_roles(document: dict[str, Any], root: Path = ROOT) -> None:
    if document.get("schema") != "komms-operator-program/v1":
        raise StewardshipError("roles: unsupported schema")
    if document.get("program_status") != "prepared-not-qualified":
        raise StewardshipError("roles: program must remain prepared-not-qualified")
    if document.get("legal_entity_status") != "no-legal-entity-represented":
        raise StewardshipError("roles: legal entity status is overstated")
    if document.get("plural_operation_status") != "not-demonstrated":
        raise StewardshipError("roles: plural operation is not demonstrated")
    if document.get("private_non_collusion_status") != "not-demonstrated":
        raise StewardshipError("roles: Private non-collusion is not demonstrated")

    roles = indexed(document.get("roles"), "roles")
    if set(roles) != ROLE_IDS:
        raise StewardshipError(
            f"roles: inventory mismatch missing={sorted(ROLE_IDS - set(roles))} "
            f"extra={sorted(set(roles) - ROLE_IDS)}"
        )
    implemented_paths = {
        "bootstrap-kad-cache": "deploy/reference-service",
        "pairwise-rendezvous": "deploy/reference-service",
        "mailbox-v2": "deploy/mailbox-service",
        "ohttp-ingress": "deploy/ohttp-relay",
        "native-wake": "deploy/wake-gateway",
    }
    for identifier, path in implemented_paths.items():
        role = roles[identifier]
        if role.get("implementation_status") != "implemented":
            raise StewardshipError(f"{identifier}: implemented status was lost")
        if role.get("deployment_status") in {"deployed", "qualified", "production"}:
            raise StewardshipError(f"{identifier}: deployment is not evidenced")
        if role.get("image_profile") != path or not (root / path).exists():
            raise StewardshipError(f"{identifier}: deployment profile is missing")
        if role.get("independent_operator_evidence") != "unassigned":
            raise StewardshipError(f"{identifier}: independent evidence is unassigned")
        if role.get("aggregate_health_only") is not True:
            raise StewardshipError(f"{identifier}: aggregate-only health is required")
        forbidden = role.get("must_not_receive")
        if not isinstance(forbidden, list) or not {
            "message-plaintext",
            "account-private-key",
            "release-signing-key",
            "provider-directory-signing-key",
        } <= set(forbidden):
            raise StewardshipError(f"{identifier}: authority exclusions are incomplete")

    mailbox = roles["mailbox-v2"]
    if (
        mailbox.get("deployability") != "dedicated-service"
        or mailbox.get("artifact") != "kult-mailbox"
        or mailbox.get("protocols") != ["/komms/mailbox/2"]
        or "open_isolation_gap" in mailbox
    ):
        raise StewardshipError("mailbox-v2: dedicated least-authority boundary is malformed")
    reference_deployability = {
        roles["bootstrap-kad-cache"].get("deployability"),
        roles["pairwise-rendezvous"].get("deployability"),
    }
    if reference_deployability != {"role-selectable-reference-service"}:
        raise StewardshipError("reference roles: selectable deployment status is inaccurate")
    split_profile = root / "deploy/reference-service/compose-split.yaml"
    if not split_profile.is_file():
        raise StewardshipError("reference roles: split deployment profile is missing")

    ohttp = roles["ohttp-ingress"]
    if (
        ohttp.get("implementation_status") != "implemented"
        or ohttp.get("deployment_status") != "not-deployed"
        or ohttp.get("deployability") != "dedicated-service-one-fixed-mapping"
        or ohttp.get("artifact") != "kult-ohttp-relay"
        or ohttp.get("image_profile") != "deploy/ohttp-relay"
        or ohttp.get("protocols") != ["rfc9458-oblivious-relay-resource"]
        or ohttp.get("credentials")
        != ["dedicated-relay-tls-private-key", "pinned-gateway-ca-bundle"]
        or "gateway-hpke-private-key" not in ohttp.get("must_not_receive", [])
        or not isinstance(ohttp.get("open_qualification_gap"), str)
        or "open_isolation_gap" in ohttp
    ):
        raise StewardshipError("ohttp-ingress: fixed least-authority boundary is malformed")


def validate_operator_records(document: dict[str, Any]) -> None:
    if document.get("schema") != "komms-operator-record-set/v1":
        raise StewardshipError("operator records: unsupported schema")
    if document.get("qualification_status") != "no-qualified-external-operators":
        raise StewardshipError("operator records: external qualification is overstated")
    records = document.get("records")
    if not isinstance(records, list) or len(records) != 2:
        raise StewardshipError("operator records: exactly two external slots are required")
    slots: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise StewardshipError("operator records: malformed slot")
        slot = record.get("slot")
        if not isinstance(slot, str) or slot in slots:
            raise StewardshipError("operator records: missing or duplicate slot")
        slots.add(slot)
        if record.get("status") != "unassigned" or record.get("qualified") is not False:
            raise StewardshipError(f"{slot}: no external operator is qualified")
        for field in (
            "operator_name",
            "administrative_domain",
            "hosting_provider",
            "source_revision",
            "independence_attestation",
        ):
            if record.get(field) is not None:
                raise StewardshipError(f"{slot}: {field} must remain unassigned")
        for field in (
            "image_digests",
            "enabled_roles",
            "service_key_fingerprints",
            "capacity_observations",
            "upgrade_rollback_runs",
            "abuse_incident_runs",
            "conformance_results",
        ):
            if record.get(field) != []:
                raise StewardshipError(f"{slot}: {field} contains invented evidence")


def validate_flows(document: dict[str, Any]) -> None:
    if document.get("schema") != "komms-provider-data-flow-inventory/v1":
        raise StewardshipError("data flows: unsupported schema")
    flows = indexed(document.get("flows"), "data flows")
    if set(flows) != FLOW_IDS:
        raise StewardshipError("data flows: role/provider coverage is incomplete")
    for identifier, flow in flows.items():
        if flow.get("content_plaintext_visible") is not False:
            raise StewardshipError(f"{identifier}: plaintext boundary is malformed")
        risk = flow.get("cross_role_correlation_risk")
        if not isinstance(risk, str) or not risk.strip():
            raise StewardshipError(f"{identifier}: correlation risk is missing")
    ohttp = flows["ohttp-private"]
    if (
        ohttp.get("actors")
        != [
            "endpoint",
            "ohttp-relay-operator",
            "ohttp-gateway-operator",
            "protected-target",
            "hosting-and-network-providers",
        ]
        or "local relay artifact is not an end-to-end path"
        not in str(ohttp.get("cross_role_correlation_risk"))
        or "no project deployment exists"
        not in str(ohttp.get("project_service_retention"))
        or "gateway-sees-decapsulated-target-method-uri-headers-and-body"
        not in ohttp.get("operator_visibility", [])
    ):
        raise StewardshipError("ohttp-private: qualification boundary is overstated")
    request = document.get("lawful_request_rule")
    if not isinstance(request, dict):
        raise StewardshipError("data flows: lawful-request rule is missing")
    required_true = {
        "verify_legal_process",
        "minimize_and_preserve_objections",
        "do_not_create_unheld_data",
        "do_not_claim_inability_to_observe",
        "notify_affected_users_when_legally_permitted_and_safe",
        "publish_aggregate_transparency_record",
    }
    if any(request.get(field) is not True for field in required_true):
        raise StewardshipError("data flows: lawful-request minimization is incomplete")
    if request.get("qualified_counsel") != "unassigned":
        raise StewardshipError("data flows: qualified counsel remains unassigned")


def validate_funding(document: dict[str, Any]) -> None:
    if document.get("schema") != "komms-funding-transparency/v1":
        raise StewardshipError("funding: unsupported schema")
    entity = document.get("legal_entity")
    accounts = document.get("accounts")
    if not isinstance(entity, dict) or entity.get("exists") is not False:
        raise StewardshipError("funding: no legal entity is represented")
    if not isinstance(accounts, dict) or accounts.get(
        "dedicated_project_account_exists"
    ) is not False:
        raise StewardshipError("funding: no dedicated account is represented")
    for field in ("opening_balance", "closing_balance"):
        if accounts.get(field) is not None:
            raise StewardshipError(f"funding: {field} must not invent an amount")
    for field in (
        "official_income",
        "official_expenditure",
        "infrastructure_costs",
        "grants",
        "sponsors",
        "paid_work",
        "conflicts",
    ):
        if not isinstance(document.get(field), list):
            raise StewardshipError(f"funding: {field} must be an explicit list")
    if document.get("review_status") != (
        "initial-structure-complete-financial-attestation-open"
    ):
        raise StewardshipError("funding: founder financial attestation remains open")


def validate_assets(document: dict[str, Any], root: Path = ROOT) -> None:
    if document.get("schema") != "komms-license-asset-inventory/v1":
        raise StewardshipError("assets: unsupported schema")
    if document.get("project_license") != "AGPL-3.0-only":
        raise StewardshipError("assets: project license must remain AGPL-3.0-only")
    packages = document.get("package_identifiers")
    if not isinstance(packages, list):
        raise StewardshipError("assets: package identifiers are missing")
    app_ids = {
        record.get("identifier")
        for record in packages
        if isinstance(record, dict)
        and record.get("platform") in {"desktop", "android", "ios"}
    }
    if app_ids != {"is.andri.komms"}:
        raise StewardshipError("assets: application identifiers disagree")
    container_ids = {
        record.get("identifier")
        for record in packages
        if isinstance(record, dict) and record.get("platform") == "container"
    }
    expected_containers = {
        "ghcr.io/andrigitdev/komms-kultd",
        "ghcr.io/andrigitdev/komms-reference-service",
        "ghcr.io/andrigitdev/komms-mailbox",
        "ghcr.io/andrigitdev/komms-wake",
        "ghcr.io/andrigitdev/komms-ohttp-relay",
    }
    if container_ids != expected_containers:
        raise StewardshipError("assets: container identifiers disagree")
    material = indexed(document.get("third_party_material"), "third-party material")
    bip39 = material.get("bip-39-english-wordlist")
    if (
        bip39 is None
        or bip39.get("license") != "MIT"
        or bip39.get("path") != "crates/kult-crypto/src/wordlist.rs"
        or bip39.get("notice") != "LICENSES/BIP-39-MIT.txt"
    ):
        raise StewardshipError("assets: BIP-39 MIT attribution is incomplete")
    for relative in (bip39["path"], bip39["notice"], "THIRD_PARTY_NOTICES.md"):
        if not (root / relative).is_file():
            raise StewardshipError(f"assets: missing retained notice {relative}")
    source = (root / bip39["path"]).read_text(encoding="utf-8")
    if "MIT-licensed BIP-39" not in source or "public-domain reference data" in source:
        raise StewardshipError("assets: BIP-39 source attribution is inaccurate")


def validate_tabletops(document: dict[str, Any]) -> None:
    if document.get("schema") != "komms-incident-tabletop-set/v1":
        raise StewardshipError("tabletops: unsupported schema")
    if document.get("exercise_kind") != "repository-policy-dry-run":
        raise StewardshipError("tabletops: only the recorded dry-run is evidenced")
    if document.get("independent_or_live_evidence") is not False:
        raise StewardshipError("tabletops: dry-run is not independent or live evidence")
    scenarios = indexed(document.get("scenarios"), "tabletops")
    if set(scenarios) != TABLETOP_IDS:
        raise StewardshipError("tabletops: scenario coverage is incomplete")
    required = {
        "service-key-compromise": {
            "remove-affected-default",
            "rotate-only-the-affected-credential-domain",
            "preserve-core-fallback",
        },
        "lawful-request": {
            "verify-authority-and-scope",
            "inventory-only-data-actually-held",
            "publish-aggregate-transparency-record",
        },
        "cross-role-correlation": {
            "withdraw-private-non-collusion-claim",
            "separate-administrative-domains-or-use-tor-only-wording",
        },
        "operator-overload-and-eol": {
            "refuse-new-custody-before-overcommit",
            "preserve-client-fallback-and-sender-custody",
            "disable-retired-service-keys",
        },
    }
    required_forbidden = {
        "service-key-compromise": {
            "import-gateway-hpke-key-into-ohttp-relay",
        },
        "cross-role-correlation": {
            "co-locate-ohttp-relay-and-gateway-while-claiming-private",
        },
        "operator-overload-and-eol": {
            "retry-ambiguous-ohttp-request",
        },
    }
    for identifier, expected in required.items():
        scenario = scenarios[identifier]
        actions = scenario.get("required_actions")
        forbidden = scenario.get("forbidden_actions")
        if not isinstance(actions, list) or not expected <= set(actions):
            raise StewardshipError(f"{identifier}: containment sequence is incomplete")
        if not isinstance(forbidden, list) or not forbidden:
            raise StewardshipError(f"{identifier}: unsafe shortcuts are not recorded")
        if not required_forbidden.get(identifier, set()) <= set(forbidden):
            raise StewardshipError(f"{identifier}: OHTTP unsafe shortcuts are incomplete")
        result = scenario.get("dry_run_result")
        if not isinstance(result, str) or not result.startswith("pass-with-"):
            raise StewardshipError(f"{identifier}: dry-run result is malformed")


def validate_docs(root: Path = ROOT) -> None:
    for relative, phrases in REQUIRED_DOCS.items():
        path = root / relative
        if not path.is_file():
            raise StewardshipError(f"{relative}: policy document is missing")
        source = path.read_text(encoding="utf-8")
        folded = source.casefold()
        for phrase in phrases:
            if phrase.casefold() not in folded:
                raise StewardshipError(f"{relative}: required boundary {phrase!r} is missing")
    license_policy = (root / "docs/47-license-trademark-assets.md").read_text(
        encoding="utf-8"
    )
    if re.search(r"\b(?:noncommercial|no government use|ethical use only)\b", license_policy, re.I):
        raise StewardshipError("license policy: an AGPL field-of-use restriction was added")
    for relative in (
        "docs/reference-service-operator.md",
        "docs/wake-gateway-operator.md",
        "docs/ohttp-relay-operator.md",
    ):
        source = (root / relative).read_text(encoding="utf-8")
        if "**Not deployed**" not in source:
            raise StewardshipError(f"{relative}: undeployed status is missing")


def validate(root: Path = ROOT) -> None:
    validate_roles(read_json(root, "operations/v1/roles.json"), root)
    validate_operator_records(read_json(root, "operations/v1/operator-records.json"))
    validate_flows(read_json(root, "operations/v1/data-flows.json"))
    validate_funding(read_json(root, "operations/v1/funding-report.json"))
    validate_assets(read_json(root, "operations/v1/assets.json"), root)
    validate_tabletops(read_json(root, "operations/v1/tabletops.json"))
    validate_docs(root)


def main() -> None:
    try:
        validate()
    except StewardshipError as error:
        raise SystemExit(f"stewardship check failed: {error}") from error
    print(
        "operator roles, external slots, provider flows, funding, assets, "
        "and incident dry-runs are internally consistent"
    )


if __name__ == "__main__":
    main()
