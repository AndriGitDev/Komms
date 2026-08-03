#!/usr/bin/env python3
"""Regression tests for the stewardship policy validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-stewardship.py"
SPEC = importlib.util.spec_from_file_location("check_stewardship", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def record(path: str) -> dict[str, object]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class StewardshipTests(unittest.TestCase):
    def test_checked_in_program_is_valid(self) -> None:
        CHECK.validate()

    def test_invented_plural_operation_is_rejected(self) -> None:
        document = record("operations/v1/roles.json")
        document["plural_operation_status"] = "qualified"
        with self.assertRaisesRegex(CHECK.StewardshipError, "plural operation"):
            CHECK.validate_roles(document)

    def test_invented_external_operator_is_rejected(self) -> None:
        document = record("operations/v1/operator-records.json")
        candidate = document["records"][0]
        candidate["status"] = "qualified"
        candidate["qualified"] = True
        candidate["operator_name"] = "Example"
        with self.assertRaisesRegex(CHECK.StewardshipError, "no external operator"):
            CHECK.validate_operator_records(document)

    def test_ohttp_overclaim_is_rejected(self) -> None:
        document = record("operations/v1/roles.json")
        candidate = next(
            role for role in document["roles"] if role["id"] == "ohttp-ingress"
        )
        candidate["credentials"].append("gateway-hpke-private-key")
        with self.assertRaisesRegex(CHECK.StewardshipError, "ohttp-ingress"):
            CHECK.validate_roles(document)

    def test_ohttp_collusion_overclaim_is_rejected(self) -> None:
        document = record("operations/v1/data-flows.json")
        candidate = next(
            flow for flow in document["flows"] if flow["id"] == "ohttp-private"
        )
        candidate["cross_role_correlation_risk"] = "anonymous by construction"
        with self.assertRaisesRegex(CHECK.StewardshipError, "ohttp-private"):
            CHECK.validate_flows(document)

    def test_mailbox_role_expansion_is_rejected(self) -> None:
        document = record("operations/v1/roles.json")
        candidate = next(
            role for role in document["roles"] if role["id"] == "mailbox-v2"
        )
        candidate["protocols"].append("/komms/envelope/2")
        with self.assertRaisesRegex(CHECK.StewardshipError, "mailbox-v2"):
            CHECK.validate_roles(document)

    def test_reference_role_rebundling_is_rejected(self) -> None:
        document = record("operations/v1/roles.json")
        candidate = next(
            role
            for role in document["roles"]
            if role["id"] == "bootstrap-kad-cache"
        )
        candidate["deployability"] = "co-bundled-reference-service"
        with self.assertRaisesRegex(CHECK.StewardshipError, "reference roles"):
            CHECK.validate_roles(document)

    def test_missing_lawful_request_minimization_is_rejected(self) -> None:
        document = record("operations/v1/data-flows.json")
        document["lawful_request_rule"]["do_not_create_unheld_data"] = False
        with self.assertRaisesRegex(CHECK.StewardshipError, "lawful-request"):
            CHECK.validate_flows(document)

    def test_invented_financial_balance_is_rejected(self) -> None:
        document = record("operations/v1/funding-report.json")
        document["accounts"]["closing_balance"] = 0
        with self.assertRaisesRegex(CHECK.StewardshipError, "closing_balance"):
            CHECK.validate_funding(document)

    def test_bip39_public_domain_claim_is_rejected(self) -> None:
        document = record("operations/v1/assets.json")
        candidate = next(
            item
            for item in document["third_party_material"]
            if item["id"] == "bip-39-english-wordlist"
        )
        candidate["license"] = "CC0-1.0"
        with self.assertRaisesRegex(CHECK.StewardshipError, "BIP-39 MIT"):
            CHECK.validate_assets(document)

    def test_missing_incident_containment_is_rejected(self) -> None:
        document = record("operations/v1/tabletops.json")
        candidate = next(
            item
            for item in document["scenarios"]
            if item["id"] == "service-key-compromise"
        )
        candidate["required_actions"].remove("preserve-core-fallback")
        with self.assertRaisesRegex(CHECK.StewardshipError, "containment sequence"):
            CHECK.validate_tabletops(document)

    def test_live_or_independent_dry_run_claim_is_rejected(self) -> None:
        document = copy.deepcopy(record("operations/v1/tabletops.json"))
        document["independent_or_live_evidence"] = True
        with self.assertRaisesRegex(CHECK.StewardshipError, "not independent"):
            CHECK.validate_tabletops(document)


if __name__ == "__main__":
    unittest.main()
