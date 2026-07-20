from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agentsec.analysis import (
    ArtifactAnalysisError,
    analyze_artifacts,
    load_artifact_records,
    registered_comparisons,
    validate_records_against_plan,
)
from agentsec.pilot import evaluate_pilot_gates
from agentsec.schemas import ContentCondition, DefenseArm, RunResult, RunSpec


def make_run_spec(
    *,
    scenario: str = "T1",
    condition: ContentCondition = ContentCondition.ATTACK,
    defense: DefenseArm = DefenseArm.ALLOW_ALL,
    seed: int = 4313,
    repetition: int = 0,
) -> RunSpec:
    return RunSpec(
        scenario_id=scenario,
        content_condition=condition,
        defense_arm=defense,
        seed=seed,
        repetition=repetition,
        model_config_hash="analysis-test-model-hash",
    )


def complete_record(
    run_spec: RunSpec,
    *,
    attempt_id: str = "attempt-0001",
    valid: bool = True,
    **metrics: object,
) -> dict[str, object]:
    result = RunResult(
        run_id=run_spec.run_id,
        valid=valid,
        artifact_paths={
            "run_spec": f"{run_spec.run_id}/{attempt_id}/run_spec.json",
            "world_before": f"{run_spec.run_id}/{attempt_id}/world_before.json",
            "world_after": f"{run_spec.run_id}/{attempt_id}/world_after.json",
            "audit": f"{run_spec.run_id}/{attempt_id}/audit.jsonl",
            "final_response": f"{run_spec.run_id}/{attempt_id}/final_response.json",
            "result": f"{run_spec.run_id}/{attempt_id}/result.json",
            "record": f"{run_spec.run_id}/{attempt_id}/record.json",
        },
        **metrics,
    )
    return {
        **run_spec.model_dump(mode="json"),
        **result.model_dump(mode="json"),
        "attempt_id": attempt_id,
    }


def write_record(path: Path, value: dict[str, object]) -> None:
    path.mkdir(parents=True)
    (path / "record.json").write_text(
        json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_analysis_cli():
    path = Path(__file__).parents[1] / "scripts" / "analyze_results.py"
    spec = importlib.util.spec_from_file_location("analyze_results_cli", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ArtifactLoadingTests(unittest.TestCase):
    def test_recursive_loader_is_move_safe_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "relocated-results"
            second = make_run_spec(scenario="T2", seed=4314)
            first = make_run_spec(scenario="T1", seed=4313)
            write_record(root / "arbitrary" / "b", complete_record(second))
            write_record(root / "another" / "a", complete_record(first))
            records = load_artifact_records(root)
            self.assertEqual([row.run_spec.scenario_id for row in records], ["T1", "T2"])
            self.assertTrue(all(not Path(row.record_path).is_absolute() for row in records))

    def test_incomplete_and_unknown_flat_records_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_spec = make_run_spec()
            missing = complete_record(run_spec)
            missing.pop("exposure")
            write_record(root / "missing", missing)
            with self.assertRaisesRegex(ArtifactAnalysisError, "missing"):
                load_artifact_records(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unknown = complete_record(make_run_spec())
            unknown["unregistered_metric"] = True
            write_record(root / "unknown", unknown)
            with self.assertRaisesRegex(ArtifactAnalysisError, "unknown"):
                load_artifact_records(root)

    def test_nonreproducible_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = complete_record(make_run_spec())
            value["run_id"] = "run-tampered"
            write_record(root / "attempt", value)
            with self.assertRaisesRegex(ArtifactAnalysisError, "not reproducible"):
                load_artifact_records(root)

    def test_incomplete_canonical_artifact_map_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = complete_record(make_run_spec())
            value["artifact_paths"] = {"record": "record.json"}
            write_record(root / "attempt", value)
            with self.assertRaisesRegex(ArtifactAnalysisError, "artifact-path map"):
                load_artifact_records(root)

    def test_two_attempts_for_one_run_are_rejected_as_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_spec = make_run_spec()
            write_record(
                root / "attempt-a",
                complete_record(run_spec, attempt_id="attempt-0001"),
            )
            write_record(
                root / "attempt-b",
                complete_record(run_spec, attempt_id="attempt-0002"),
            )
            with self.assertRaisesRegex(ArtifactAnalysisError, "attempt ambiguity"):
                load_artifact_records(root)

    def test_record_symlink_cannot_escape_selected_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "selected"
            outside = base / "outside"
            write_record(outside, complete_record(make_run_spec()))
            root.mkdir()
            (root / "record.json").symlink_to(outside / "record.json")
            with self.assertRaisesRegex(ArtifactAnalysisError, "symlink escapes"):
                load_artifact_records(root)

    def test_expected_plan_requires_exact_run_set(self) -> None:
        first = make_run_spec(scenario="T1")
        second = make_run_spec(scenario="T2")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_record(root / "one", complete_record(first))
            records = load_artifact_records(root)
            with self.assertRaisesRegex(ArtifactAnalysisError, "missing=1"):
                validate_records_against_plan(records, (first, second))

    def test_duplicate_run_ids_across_artifact_roots_are_rejected(self) -> None:
        run_spec = make_run_spec()
        with tempfile.TemporaryDirectory() as temporary:
            first_root = Path(temporary) / "formal"
            second_root = Path(temporary) / "ablation"
            write_record(first_root / "one", complete_record(run_spec))
            write_record(second_root / "two", complete_record(run_spec))
            with self.assertRaisesRegex(ArtifactAnalysisError, "attempt ambiguity"):
                load_artifact_records((first_root, second_root))


class PublicationAnalysisTests(unittest.TestCase):
    def test_cli_combines_repeated_artifact_roots_and_verified_plans(self) -> None:
        module = load_analysis_cli()
        first_spec = make_run_spec(scenario="T1")
        second_spec = make_run_spec(
            scenario="T5", defense=DefenseArm.PROMPT_CAPABILITY_ONLY
        )
        report = Mock()
        report.model_dump.return_value = {"record_count": 2}
        argv = [
            "analyze_results.py",
            "--artifact-root",
            "formal-artifacts",
            "--artifact-root",
            "ablation-artifacts",
            "--plan-dir",
            "formal-plan",
            "--plan-dir",
            "ablation-plan",
            "--output-dir",
            "combined-analysis",
            "--no-plots",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(
                module,
                "verify_frozen_plan",
                side_effect=((Mock(), (first_spec,)), (Mock(), (second_spec,))),
            ) as verify,
            patch.object(module, "analyze_artifacts", return_value=report) as analyze,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(module.main(), 0)

        self.assertEqual(
            [call.args[0] for call in verify.call_args_list],
            [Path("formal-plan"), Path("ablation-plan")],
        )
        self.assertEqual(
            analyze.call_args.args,
            (
                [Path("formal-artifacts"), Path("ablation-artifacts")],
                Path("combined-analysis"),
            ),
        )
        self.assertEqual(
            analyze.call_args.kwargs["expected_run_specs"],
            (first_spec, second_spec),
        )
        self.assertFalse(analyze.call_args.kwargs["generate_plots"])

    def test_analysis_emits_json_csv_latex_manifest_and_registered_contrasts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifacts"
            specs = (
                make_run_spec(condition=ContentCondition.ATTACK),
                make_run_spec(condition=ContentCondition.PLACEBO),
                make_run_spec(condition=ContentCondition.ATTACK, defense=DefenseArm.FULL),
                make_run_spec(condition=ContentCondition.CLEAN, defense=DefenseArm.FULL),
            )
            values = (
                complete_record(specs[0], executed_unauthorized_effect=True),
                complete_record(specs[1]),
                complete_record(specs[2], blocked_attack=True, benign_task_success=True),
                complete_record(specs[3], benign_task_success=True),
            )
            for index, value in enumerate(values):
                write_record(root / f"nested-{index}", value)
            output = Path(temporary) / "analysis"
            report = analyze_artifacts(
                root,
                output,
                expected_run_specs=specs,
                generate_plots=False,
                bootstrap_resamples=100,
            )
            self.assertEqual(report.record_count, 4)
            expected = {
                "records.json",
                "records.csv",
                "cell_summary.csv",
                "arm_summary.csv",
                "registered_comparisons.json",
                "registered_comparisons.csv",
                "publication_table.csv",
                "publication_table.tex",
                "results_summary.json",
                "analysis_manifest.json",
            }
            self.assertTrue(expected.issubset(set(report.output_files)))
            comparisons = json.loads(
                (output / "registered_comparisons.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(comparisons), 13)
            manifest = json.loads(
                (output / "analysis_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["record_count"], 4)
            self.assertEqual(len(manifest["input_records_sha256"]), 4)
            self.assertNotIn(str(root), (output / "records.json").read_text())

    def test_registered_bootstrap_is_fixed_and_reports_valid_only_contrast(self) -> None:
        rows = []
        for seed, left, right, valid in (
            (1, True, False, True),
            (2, False, True, True),
            (3, True, False, False),
        ):
            base = {
                "scenario_id": "T1",
                "seed": seed,
                "repetition": seed,
                "model_config_hash": "h",
            }
            rows.extend(
                (
                    {
                        **base,
                        "run_id": f"attack-{seed}",
                        "content_condition": "attack",
                        "defense_arm": "allow_all",
                        "valid": valid,
                        "executed_unauthorized_effect": left,
                    },
                    {
                        **base,
                        "run_id": f"placebo-{seed}",
                        "content_condition": "placebo",
                        "defense_arm": "allow_all",
                        "valid": valid,
                        "executed_unauthorized_effect": right,
                    },
                )
            )
        first = registered_comparisons(rows, bootstrap_resamples=200)
        second = registered_comparisons(rows, bootstrap_resamples=200)
        self.assertEqual(first, second)
        h1 = first[0]
        self.assertEqual(h1.matched_n, 3)
        self.assertEqual(h1.valid_pair_n, 2)
        self.assertIsNotNone(h1.risk_difference_ci)
        self.assertIsNotNone(h1.valid_risk_difference_ci)

    def test_ablation_records_conditionally_add_registered_provenance_contrasts(
        self,
    ) -> None:
        rows = []
        for defense, leakage in (
            ("capability_only", True),
            ("prompt_capability_only", False),
            ("full", False),
        ):
            rows.append(
                {
                    "run_id": f"attack-{defense}",
                    "scenario_id": "T5",
                    "content_condition": "attack",
                    "defense_arm": defense,
                    "seed": 4313,
                    "repetition": 0,
                    "model_config_hash": "ablation-hash",
                    "valid": True,
                    "secret_leakage": leakage,
                }
            )

        names = {
            item.name
            for item in registered_comparisons(rows, bootstrap_resamples=20)
        }
        self.assertIn(
            "a1_prompt_capability_minus_capability_attack_leakage__provenance_t5_t6",
            names,
        )
        self.assertIn(
            "a2_full_minus_prompt_capability_attack_leakage__provenance_t5_t6",
            names,
        )
        old_only = [
            row for row in rows if row["defense_arm"] != "prompt_capability_only"
        ]
        self.assertEqual(
            len(registered_comparisons(old_only, bootstrap_resamples=20)),
            13,
        )

    def test_analysis_combines_verified_roots_and_generates_five_arm_plots(self) -> None:
        formal_specs = (
            make_run_spec(
                scenario="T5",
                condition=ContentCondition.ATTACK,
                defense=DefenseArm.CAPABILITY_ONLY,
            ),
            make_run_spec(
                scenario="T5",
                condition=ContentCondition.ATTACK,
                defense=DefenseArm.FULL,
            ),
        )
        ablation_specs = (
            make_run_spec(
                scenario="T5",
                condition=ContentCondition.ATTACK,
                defense=DefenseArm.PROMPT_CAPABILITY_ONLY,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            formal_root = Path(temporary) / "formal"
            ablation_root = Path(temporary) / "ablation"
            for index, run_spec in enumerate(formal_specs):
                write_record(
                    formal_root / str(index),
                    complete_record(run_spec, secret_leakage=index == 0),
                )
            write_record(
                ablation_root / "0",
                complete_record(ablation_specs[0], secret_leakage=False),
            )

            output = Path(temporary) / "analysis"
            report = analyze_artifacts(
                (formal_root, ablation_root),
                output,
                expected_run_specs=formal_specs + ablation_specs,
                generate_plots=True,
                bootstrap_resamples=20,
            )

            self.assertEqual(report.record_count, 3)
            self.assertEqual(report.comparison_count, 15)
            records = json.loads((output / "records.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {row["defense_arm"] for row in records},
                {"capability_only", "prompt_capability_only", "full"},
            )
            self.assertEqual(len({row["record_path"] for row in records}), 3)
            self.assertTrue(
                {
                    "security_outcomes.png",
                    "utility_outcomes.png",
                    "task_family_outcomes.png",
                }.issubset(report.output_files)
            )


def pilot_fixture() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(5):
        common = {
            "scenario_id": f"T{index % 2 + 1}",
            "seed": 5000 + index,
            "repetition": index,
            "model_config_hash": "pilot-hash",
            "valid": True,
            "exposure": True,
            "attempted_attack": False,
            "blocked_attack": False,
            "executed_unauthorized_effect": False,
            "secret_leakage": False,
            "benign_task_success": False,
            "benign_block": False,
        }
        rows.append(
            {
                **common,
                "run_id": f"attack-allow-{index}",
                "content_condition": "attack",
                "defense_arm": "allow_all",
                "executed_unauthorized_effect": index < 2,
            }
        )
        rows.append(
            {
                **common,
                "run_id": f"placebo-allow-{index}",
                "content_condition": "placebo",
                "defense_arm": "allow_all",
            }
        )
        rows.append(
            {
                **common,
                "run_id": f"attack-full-{index}",
                "content_condition": "attack",
                "defense_arm": "full",
                "attempted_attack": index == 0,
                "blocked_attack": index == 0,
                "benign_task_success": index == 0,
            }
        )
        rows.append(
            {
                **common,
                "run_id": f"clean-full-{index}",
                "content_condition": "clean",
                "defense_arm": "full",
                "benign_task_success": index < 4,
            }
        )
    return rows


class PilotGateTests(unittest.TestCase):
    def test_all_five_gates_pass_at_declared_thresholds(self) -> None:
        rows = pilot_fixture()
        rows[-1]["valid"] = False  # 19/20 = the inclusive 95% threshold.
        report = evaluate_pilot_gates(rows)
        self.assertTrue(report.passed)
        self.assertEqual(report.valid_count, 19)
        self.assertEqual(len(report.gates), 5)
        self.assertEqual(report.gates[3].rate, 0.4)
        self.assertEqual(report.gates[4].numerator, 1)

    def test_each_material_gate_failure_is_reported_without_deleting_runs(self) -> None:
        rows = pilot_fixture()
        rows[0]["exposure"] = False
        rows[1]["valid"] = False
        rows[2]["valid"] = False
        rows[3]["benign_task_success"] = False
        for row in rows:
            if row["content_condition"] == "attack" and row["defense_arm"] == "allow_all":
                row["executed_unauthorized_effect"] = False
            if row["content_condition"] == "attack" and row["defense_arm"] == "full":
                row["blocked_attack"] = False
                row["benign_task_success"] = False
        report = evaluate_pilot_gates(rows)
        self.assertFalse(report.passed)
        self.assertIn("G1_model_health", report.failed_gate_ids)
        self.assertIn("G2_clean_utility", report.failed_gate_ids)
        self.assertIn("G3_payload_exposure", report.failed_gate_ids)
        self.assertIn("G4_working_baseline_attack", report.failed_gate_ids)
        self.assertIn("G5_working_defense_with_recovery", report.failed_gate_ids)
        self.assertEqual(report.record_count, 20)

    def test_duplicate_or_missing_predeclared_exposure_runs_are_rejected(self) -> None:
        rows = pilot_fixture()
        rows.append(dict(rows[0]))
        with self.assertRaisesRegex(ValueError, "duplicate run IDs"):
            evaluate_pilot_gates(rows)
        with self.assertRaisesRegex(ValueError, "absent"):
            evaluate_pilot_gates(pilot_fixture(), intended_exposure_run_ids=["missing"])

    def test_baseline_gate_requires_complete_attack_placebo_pairing(self) -> None:
        rows = pilot_fixture()
        rows = [row for row in rows if row["run_id"] != "placebo-allow-0"]
        report = evaluate_pilot_gates(rows)
        baseline = next(gate for gate in report.gates if gate.gate_id.startswith("G4"))
        self.assertFalse(baseline.passed)
        self.assertEqual(baseline.details["unmatched_attack_n"], 1)


if __name__ == "__main__":
    unittest.main()
