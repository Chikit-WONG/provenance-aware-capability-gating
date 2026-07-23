"""Focused contracts for native AgentDojo analysis."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from agentsec.agentdojo_external import (
    AgentDojoFrozenManifest,
    AgentDojoResultRecord,
    AgentDojoRunSpec,
    canonical_pair,
    build_formal_plan,
    select_agentdojo_pairs,
)
from agentsec.attempts import AttemptSelection, AttemptSelectionManifest, AttemptStatus
from agentsec.aggregate import wilson_interval


MODEL_HASH = "a" * 64
CHECKPOINT_HASH = "b" * 64
MODEL_PATH = "/tmp/qwen"
MODEL_NAME = "qwen3-vl-8b"


def _plan_rows() -> list[AgentDojoRunSpec]:
    pairs = select_agentdojo_pairs(
        [canonical_pair(f"u{i}", f"i{i}") for i in range(18)]
    )[2:]
    return build_formal_plan(pairs, MODEL_HASH)


def _records(rows: list[AgentDojoRunSpec]) -> list[AgentDojoResultRecord]:
    values: list[AgentDojoResultRecord] = []
    for index, row in enumerate(rows):
        attacked = row.attack != "none"
        values.append(
            AgentDojoResultRecord(
                run_spec=row,
                attempt_id="attempt-0001",
                valid=True,
                utility=index % 2 == 0,
                targeted_attack_success=(index % 3 == 0) if attacked else None,
                official_security_value=(index % 3 == 0) if attacked else None,
            )
        )
    return values


def _selection(rows: list[AgentDojoRunSpec], plan_hash: str) -> AttemptSelectionManifest:
    return AttemptSelectionManifest(
        plan_sha256=plan_hash,
        rows=tuple(
            AttemptSelection(
                run_id=row.run_id,
                initial_status=AttemptStatus.COMPLETE,
                initial_record_sha256="c" * 64,
                selected_attempt="attempt-0001",
                selected_record_sha256="c" * 64,
                conservative_utility=False,
                conservative_targeted_attack_success=(row.attack != "none"),
            )
            for row in rows
        ),
    )


class AgentDojoExternalAnalysisTests(unittest.TestCase):
    def test_validation_rejects_missing_extra_duplicate_development_and_hash_drift(self) -> None:
        from agentsec.agentdojo_external_analysis import validate_formal_records

        rows = _plan_rows()
        records = _records(rows)
        plan_hash = "d" * 64
        manifest = _selection(rows, plan_hash)
        validate_formal_records(records, rows, manifest, plan_hash)
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_formal_records(records[:-1], rows, manifest, plan_hash)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_formal_records([*records, records[0]], rows, manifest, plan_hash)
        with self.assertRaisesRegex(ValueError, "unexpected|extra"):
            extra = AgentDojoResultRecord(
                phase="formal", user_task_id="extra", injection_task_id="i",
                attack="important_instructions", defense="none",
                model_config_hash=MODEL_HASH, run_id="extra-run",
                attempt_id="attempt-0001", valid=True, utility=True,
                targeted_attack_success=False, official_security_value=False,
            )
            validate_formal_records([*records, extra], rows, manifest, plan_hash)
        development = records[0].model_copy(update={"phase": "development"})
        with self.assertRaisesRegex(ValueError, "development"):
            validate_formal_records([development, *records[1:]], rows, manifest, plan_hash)
        with self.assertRaisesRegex(ValueError, "plan_sha256"):
            validate_formal_records(records, rows, manifest, "e" * 64)

    def test_attack_and_clean_summaries_keep_official_semantics_and_wilson_intervals(self) -> None:
        from agentsec.agentdojo_external_analysis import summarize_records

        rows = _plan_rows()
        records = _records(rows)
        # Force one infrastructure-invalid attacked row; ITT is conservative.
        invalid = records[0].model_copy(
            update={"valid": False, "invalid_reason": "model_timeout", "utility": None}
        )
        records[0] = invalid
        report = summarize_records(records)
        attacked = report["attack_summary"]
        self.assertEqual({(r["attack"], r["defense"]) for r in attacked}, {
            ("important_instructions", "none"),
            ("important_instructions", "repeat_user_prompt"),
            ("tool_knowledge", "none"),
            ("tool_knowledge", "repeat_user_prompt"),
        })
        first = next(r for r in attacked if r["attack"] == "important_instructions" and r["defense"] == "none")
        self.assertIn("targeted_asr", first)
        self.assertIn("utility_under_attack", first)
        self.assertEqual(first["planned_n"], first["valid_n"] + first["invalid_n"])
        self.assertAlmostEqual(first["targeted_asr"]["itt_rate"], 6 / 16)
        self.assertAlmostEqual(first["utility_under_attack"]["itt_rate"], 15 / 16)
        clean = report["clean_utility"]
        self.assertEqual({row["defense"] for row in clean}, {"none", "repeat_user_prompt"})
        expected = wilson_interval(16, 16)
        clean_none = next(row for row in clean if row["defense"] == "none")
        self.assertAlmostEqual(clean_none["utility_without_attack"]["wilson"]["lower"], expected.lower)


if __name__ == "__main__":
    unittest.main()
