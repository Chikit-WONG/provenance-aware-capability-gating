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



    def test_scheduler_label_cannot_override_behavioral_invalid_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = _spec()
            path = root / spec.run_id / "attempt-0001" / "record.json"
            path.parent.mkdir(parents=True)
            path.write_text(_record(spec, "attempt-0001", valid=False, invalid_reason="tool_call_parse_error", error="bad").model_dump_json())
            row = build_attempt_selection([spec], root, interruptions={spec.run_id: "scheduler_termination"}).rows[0]
            self.assertIsNone(row.recovered_attempt)
            self.assertEqual(row.selected_attempt, "attempt-0001")

    def test_partial_initial_record_is_retained_with_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = _spec()
            path = root / spec.run_id / "attempt-0001" / "record.json"
            path.parent.mkdir(parents=True)
            path.write_text("{\"run_id\":\"partial\"}\n")
            row = build_attempt_selection([spec], root).rows[0]
            self.assertEqual(row.initial_status, AttemptStatus.INVALID)
            self.assertRegex(row.initial_record_sha256, r"^[0-9a-f]{64}$")
            self.assertIsNone(row.selected_attempt)

    def test_invalid_recovery_is_not_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = _spec()
            for attempt, valid, reason in (("attempt-0001", False, "model_timeout"), ("attempt-0002", False, "model_timeout")):
                path = root / spec.run_id / attempt / "record.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(_record(spec, attempt, valid=valid, invalid_reason=reason, utility=None, targeted_attack_success=None, official_security_value=None, error="timeout").model_dump_json())
            row = build_attempt_selection([spec], root).rows[0]
            self.assertEqual(row.recovered_status, AttemptStatus.INVALID)
            self.assertEqual(row.selected_attempt, "attempt-0001")
            self.assertTrue(row.conservative_targeted_attack_success)



    def test_resume_skips_complete_record_before_pipeline_creation(self) -> None:
        import importlib.util
        script_path = Path("scripts/run_agentdojo_external.py")
        spec_module = importlib.util.spec_from_file_location("run_agentdojo_external_resume", script_path)
        module = importlib.util.module_from_spec(spec_module)
        assert spec_module.loader is not None
        spec_module.loader.exec_module(module)
        row = _spec()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plan_path = root / "formal_plan.jsonl"
            plan_path.write_text(row.model_dump_json() + "\n")
            record_path = root / "runs" / row.run_id / "attempt-0001" / "record.json"
            record_path.parent.mkdir(parents=True)
            record_path.write_text(_record(row, "attempt-0001").model_dump_json())
            module.build_pipeline = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pipeline should not be built"))
            module.run_row = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("row should not rerun"))
            records = module.run_slice(plan_path, root, phase="formal", resume=True)
            self.assertEqual([record.run_id for record in records], [row.run_id])

    def test_runner_marks_missing_official_metrics_invalid(self) -> None:
        import importlib.util
        script_path = Path("scripts/run_agentdojo_external.py")
        spec_module = importlib.util.spec_from_file_location("run_agentdojo_external_metrics", script_path)
        module = importlib.util.module_from_spec(spec_module)
        assert spec_module.loader is not None
        spec_module.loader.exec_module(module)

        class Logger:
            def __init__(self, _path: str) -> None:
                pass
            def __enter__(self):
                return self
            def __exit__(self, *_args: object) -> None:
                return None

        module._output_logger = lambda: Logger
        row = _spec()
        fake_functions = (lambda *_args, **_kwargs: {"utility": None, "security": None}, lambda *_args, **_kwargs: {}, object(), object())
        with tempfile.TemporaryDirectory() as temp:
            result = module.run_row(row, pipeline=object(), artifact_root=temp, suite_functions=fake_functions)
            self.assertFalse(result.valid)
            self.assertEqual(result.invalid_reason, "official_result_missing_metric")

    def test_native_task_type_error_is_called_once(self) -> None:
        import importlib.util
        script_path = Path("scripts/run_agentdojo_external.py")
        spec = importlib.util.spec_from_file_location("run_agentdojo_external", script_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        calls = []
        def native(*args: object, **kwargs: object) -> object:
            calls.append((args, kwargs))
            raise TypeError("native failure")
        with self.assertRaises(TypeError):
            module._call_task(native, object(), object(), _spec(), attack=object())
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
