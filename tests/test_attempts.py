import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from agentsec.agentdojo_external import AgentDojoResultRecord, AgentDojoRunSpec
from agentsec.attempts import (
    AttemptStatus,
    build_attempt_selection,
    normalize_infrastructure_reason,
)


HASH = "e" * 64


def _spec(run_id: str = "run-1", attack: str = "important_instructions") -> AgentDojoRunSpec:
    return AgentDojoRunSpec(
        phase="formal",
        user_task_id="user-1",
        injection_task_id=None if attack == "none" else "injection-1",
        attack=attack,
        defense="none",
        model_config_hash=HASH,
        run_id=run_id,
    )


def _record(spec: AgentDojoRunSpec, attempt: str, **kwargs: object) -> AgentDojoResultRecord:
    return AgentDojoResultRecord(
        **spec.model_dump(),
        attempt_id=attempt,
        valid=kwargs.pop("valid", True),
        invalid_reason=kwargs.pop("invalid_reason", ""),
        utility=kwargs.pop("utility", True),
        targeted_attack_success=kwargs.pop("targeted_attack_success", False if spec.attack != "none" else None),
        official_security_value=kwargs.pop("official_security_value", False if spec.attack != "none" else None),
        **kwargs,
    )


class AttemptTests(unittest.TestCase):
    def test_missing_initial_can_select_one_declared_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = _spec()
            record_path = root / spec.run_id / "attempt-0002" / "record.json"
            record_path.parent.mkdir(parents=True)
            record_path.write_text(_record(spec, "attempt-0002").model_dump_json() + "\n")
            manifest = build_attempt_selection(
                [spec], root, interruptions={spec.run_id: "scheduler_termination"}
            )
            row = manifest.rows[0]
            self.assertEqual(row.initial_attempt, "attempt-0001")
            self.assertEqual(row.initial_status, AttemptStatus.MISSING)
            self.assertEqual(row.recovered_attempt, "attempt-0002")
            self.assertEqual(row.selected_attempt, "attempt-0002")
            self.assertRegex(row.selected_record_sha256, r"^[0-9a-f]{64}$")

    def test_behavioral_failure_does_not_select_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = _spec()
            path = root / spec.run_id / "attempt-0001" / "record.json"
            path.parent.mkdir(parents=True)
            path.write_text(_record(spec, "attempt-0001", valid=False, invalid_reason="tool_call_parse_error", error="bad").model_dump_json())
            manifest = build_attempt_selection([spec], root)
            row = manifest.rows[0]
            self.assertEqual(row.selected_attempt, "attempt-0001")
            self.assertIsNone(row.recovered_attempt)

    def test_clean_unresolved_cell_has_conservative_utility_failure_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            spec = _spec(attack="none")
            manifest = build_attempt_selection([spec], temp)
            row = manifest.rows[0]
            self.assertFalse(row.conservative_utility)
            self.assertIsNone(row.conservative_targeted_attack_success)

    def test_unregistered_reason_and_duplicate_plan_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalize_infrastructure_reason("refusal")
        spec = _spec()
        with self.assertRaises(ValueError):
            build_attempt_selection([spec, spec], tempfile.mkdtemp())

    def test_result_metric_invariants(self) -> None:
        spec = _spec()
        with self.assertRaises(ValidationError):
            _record(spec, "attempt-0001", targeted_attack_success=True, official_security_value=False)
        with self.assertRaises(ValidationError):
            _record(_spec(attack="none"), "attempt-0001", targeted_attack_success=True)


if __name__ == "__main__":
    unittest.main()
