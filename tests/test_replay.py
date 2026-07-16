from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentsec.demo import run_live_and_render
from agentsec.replay import (
    ArtifactFormatError,
    artifact_from_mapping,
    artifact_summary,
    audit_table,
    discover_attempts,
    load_replay_artifact,
    provenance_edges,
    world_delta,
)


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "demo" / "sample_blocked_attack"


class ReplayLoaderTests(unittest.TestCase):
    def test_bundled_sample_loads_and_is_clearly_nonformal(self) -> None:
        artifact = load_replay_artifact(SAMPLE)
        summary = artifact_summary(artifact)

        self.assertEqual(summary["scenario"], "DEMO-T3")
        self.assertTrue(summary["exposure"])
        self.assertTrue(summary["attempted_attack"])
        self.assertTrue(summary["blocked_attack"])
        self.assertFalse(summary["executed_unauthorized_effect"])
        self.assertTrue(summary["benign_task_success"])
        self.assertEqual(len(audit_table(artifact)), 8)

    def test_world_delta_and_provenance_are_derived_from_evidence(self) -> None:
        artifact = load_replay_artifact(SAMPLE)
        delta = world_delta(artifact)
        edges = provenance_edges(artifact)

        self.assertEqual(
            delta["new_outbox_messages"][0]["to"], "alice@example.com"
        )
        self.assertNotIn("mallory@example.com", json.dumps(delta))
        self.assertIn(
            {"from": "demo-ev-001", "to": "demo-ev-002", "relation": "parent"},
            edges,
        )

    def test_discovery_finds_nested_attempt_and_root_loader_accepts_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "run-a" / "attempt-0001"
            attempt.mkdir(parents=True)
            self._write_minimal_attempt(attempt, run_id="run-a")

            self.assertEqual(discover_attempts(temporary), [attempt.resolve()])
            self.assertEqual(load_replay_artifact(temporary).run_id, "run-a")

    def test_ambiguous_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for index in (1, 2):
                attempt = Path(temporary) / f"run-{index}" / "attempt-0001"
                attempt.mkdir(parents=True)
                self._write_minimal_attempt(attempt, run_id=f"run-{index}")

            with self.assertRaisesRegex(ArtifactFormatError, "contains 2 attempts"):
                load_replay_artifact(temporary)

    def test_mismatched_run_ids_and_nonincreasing_audit_are_rejected(self) -> None:
        mapping = self._minimal_mapping("left")
        mapping["result"]["run_id"] = "right"
        with self.assertRaisesRegex(ArtifactFormatError, "different run_id"):
            artifact_from_mapping(mapping)

        mapping = self._minimal_mapping("same")
        mapping["audit_events"] = [
            {"sequence": 2, "event_id": "one"},
            {"sequence": 2, "event_id": "two"},
        ]
        with self.assertRaisesRegex(ArtifactFormatError, "non-increasing"):
            artifact_from_mapping(mapping)

    def test_live_adapter_accepts_artifact_mapping(self) -> None:
        def runner(**kwargs: object) -> dict[str, object]:
            self.assertEqual(kwargs["scenario_id"], "T1")
            return self._minimal_mapping("live-run")

        rendered = run_live_and_render(
            runner,
            scenario_id="T1",
            content_condition="clean",
            defense_arm="full",
            seed=4313,
            artifact_root="artifacts",
        )
        self.assertEqual(rendered[0], "live in-memory result")
        self.assertIn("valid run", rendered[1])
        self.assertEqual(rendered[2]["summary"]["run_id"], "live-run")

    def test_live_adapter_accepts_concise_runner_aliases(self) -> None:
        def runner(
            scenario_id: str,
            condition: str,
            defense: str,
            seed: int,
            *,
            artifact_root: str,
        ) -> dict[str, object]:
            self.assertEqual((condition, defense), ("attack", "full"))
            return self._minimal_mapping("alias-run")

        rendered = run_live_and_render(
            runner,
            scenario_id="T1",
            content_condition="attack",
            defense_arm="full",
            seed=4313,
            artifact_root="artifacts",
        )
        self.assertEqual(rendered[2]["summary"]["run_id"], "alias-run")

    def test_loader_accepts_artifact_directory_return(self) -> None:
        artifact = artifact_from_mapping({"artifact_directory": str(SAMPLE)})
        self.assertEqual(artifact.run_id, "demo-blocked-attack")

    @staticmethod
    def _minimal_mapping(run_id: str) -> dict[str, object]:
        return {
            "run_spec": {
                "scenario_id": "T1",
                "content_condition": "clean",
                "defense_arm": "full",
                "seed": 4313,
                "run_id": run_id,
            },
            "result": {"run_id": run_id, "valid": True},
            "audit_events": [],
            "world_before": {"outbox": [], "calendar_events": {}},
            "world_after": {"outbox": [], "calendar_events": {}},
            "final_response": "done",
        }

    @classmethod
    def _write_minimal_attempt(cls, path: Path, *, run_id: str) -> None:
        mapping = cls._minimal_mapping(run_id)
        (path / "run_spec.json").write_text(
            json.dumps(mapping["run_spec"]), encoding="utf-8"
        )
        (path / "result.json").write_text(
            json.dumps(mapping["result"]), encoding="utf-8"
        )


if __name__ == "__main__":
    unittest.main()
