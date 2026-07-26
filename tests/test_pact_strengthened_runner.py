from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_pact_strengthened import (
    STRATEGY_CASE_IDS,
    normalize_email_address,
    run,
)


class StrengthenedPACTRunnerTests(unittest.TestCase):
    def test_normalize_email_address_is_exactly_trim_and_lowercase(self) -> None:
        self.assertEqual(
            "alice@example.test",
            normalize_email_address("  Alice@Example.TEST  "),
        )

    def test_runner_writes_paired_real_tool_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "pact-strengthened-v1"
            manifest = run(artifact)
            rows = json.loads((artifact / "e2e_results.json").read_text(encoding="utf-8"))

            self.assertEqual(6, len(rows))
            by_key = {(row["case_id"], row["policy"]): row for row in rows}
            external_cap = by_key[("external-bob-allowlisted", "capability_only")]
            external_pact = by_key[("external-bob-allowlisted", "pact")]
            self.assertTrue(external_cap["capability_allowed"])
            self.assertFalse(external_cap["pact_allowed"])
            self.assertTrue(external_cap["executed"])
            self.assertEqual(1, external_cap["outbox_count"])
            self.assertFalse(external_pact["enforced_allowed"])
            self.assertFalse(external_pact["executed"])
            self.assertEqual(0, external_pact["outbox_count"])
            self.assertEqual([], external_pact["tool_events"])

            for policy in ("capability_only", "pact"):
                user_bob = by_key[("user-bob", policy)]
                external_content = by_key[("external-content", policy)]
                self.assertTrue(user_bob["enforced_allowed"])
                self.assertTrue(user_bob["executed"])
                self.assertEqual(1, user_bob["outbox_count"])
                self.assertTrue(external_content["enforced_allowed"])
                self.assertTrue(external_content["executed"])
                self.assertEqual(1, external_content["outbox_count"])

            self.assertEqual(6, manifest["e2e_run_count"])

    def test_strategy_matrix_has_the_eight_registered_rows_and_decisions(self) -> None:
        expected = {
            "user-recipient-none": True,
            "external-recipient-none": False,
            "external-content-none": True,
            "user-recipient-registered": True,
            "user-recipient-unregistered": False,
            "external-recipient-registered": False,
            "user-control-none": True,
            "external-control-none": False,
        }
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "pact-strengthened-v1"
            run(artifact)
            rows = json.loads(
                (artifact / "strategy_results.json").read_text(encoding="utf-8")
            )

            self.assertEqual(tuple(expected), tuple(STRATEGY_CASE_IDS))
            self.assertEqual(set(expected), {row["case_id"] for row in rows})
            self.assertEqual(8, len(rows))
            for row in rows:
                self.assertTrue(row["capability_allowed"])
                self.assertEqual(expected[row["case_id"]], row["pact_allowed"])
                self.assertIn("role", row)
                self.assertIn("provenance_authority", row)
                self.assertIn("transform_chain", row)
                self.assertIn("provenance_digest", row)
                self.assertIn("decision_log_sha256", row)

            registered = next(
                row for row in rows if row["case_id"] == "user-recipient-registered"
            )
            self.assertTrue(registered["transformation_verified"])
            self.assertEqual("NormalizeEmailAddress", registered["transform_chain"])

            unregistered = next(
                row for row in rows if row["case_id"] == "user-recipient-unregistered"
            )
            self.assertFalse(unregistered["transformation_verified"])
            self.assertFalse(unregistered["pact_allowed"])

            external_transform = next(
                row for row in rows if row["case_id"] == "external-recipient-registered"
            )
            self.assertEqual("external", external_transform["source_authority"])
            self.assertEqual("untrusted_transform", external_transform["transform_status"])
            self.assertFalse(external_transform["pact_allowed"])

    def test_artifact_text_is_lf_only_and_manifest_hashes_final_bytes(self) -> None:
        output_names = {
            "e2e_results.json",
            "e2e_results.csv",
            "strategy_results.json",
            "strategy_results.csv",
            "decision_log.jsonl",
            "strategy_matrix.svg",
            "architecture.mmd",
        }
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "pact-strengthened-v1"
            manifest = run(artifact)
            self.assertEqual(output_names, set(manifest["outputs"]))
            self.assertEqual(manifest["outputs"], manifest["output_sha256"])
            for name in output_names | {"manifest.json"}:
                payload = (artifact / name).read_bytes()
                self.assertNotIn(b"\r", payload, name)
            for name, digest in manifest["outputs"].items():
                self.assertEqual(digest, _sha256(artifact / name))

    def test_runner_refuses_to_overwrite_an_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "pact-strengthened-v1"
            run(artifact)
            with self.assertRaises(FileExistsError):
                run(artifact)


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
