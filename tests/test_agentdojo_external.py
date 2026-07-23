import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest

from pydantic import ValidationError

from agentsec.agentdojo_external import (
    AgentDojoFrozenManifest,
    AgentDojoPair,
    AgentDojoResultRecord,
    AgentDojoRunSpec,
    build_development_plan,
    build_formal_plan,
    canonical_pair,
    select_agentdojo_pairs,
    validate_agentdojo_model_binding,
    validate_agentdojo_plan,
)


_MODEL_HASH = "e" * 64
_CHECKPOINT_HASH = "f" * 64
_MODEL_NAME = "qwen3-vl-8b"
_MODEL_PATH = "/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct"


def _candidates(count: int = 24) -> list[AgentDojoPair]:
    return [
        canonical_pair(f"user_{index % 8:02d}", f"injection_{index:02d}")
        for index in range(count)
    ]


def _valid_manifest_fields() -> dict[str, object]:
    selected = select_agentdojo_pairs(_candidates(24))
    development = selected[:2]
    formal = selected[2:]
    formal_clean_count = 2 * len({pair.user_task_id for pair in formal})
    return {
        "agentdojo_commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
        "agentdojo_tag": "v0.1.35",
        "benchmark_version": "v1.2.2",
        "suite": "workspace",
        "source_sha256": "a" * 64,
        "config_sha256": "b" * 64,
        "model_config_hash": _MODEL_HASH,
        "served_model_name": _MODEL_NAME,
        "model_checkpoint_path": _MODEL_PATH,
        "model_checkpoint_sha256": _CHECKPOINT_HASH,
        "selected_pair_ids": tuple(pair.canonical_key for pair in selected),
        "development_pair_ids": tuple(pair.canonical_key for pair in development),
        "formal_pair_ids": tuple(pair.canonical_key for pair in formal),
        "development_plan_sha256": "c" * 64,
        "formal_plan_sha256": "d" * 64,
        "selected_pair_count": 18,
        "development_pair_count": 2,
        "formal_pair_count": 16,
        "formal_attacked_count": 64,
        "formal_clean_count": formal_clean_count,
        "formal_total_count": 64 + formal_clean_count,
    }


class AgentDojoExternalTests(unittest.TestCase):
    def test_canonical_pair_uses_frozen_workspace_key(self) -> None:
        pair = canonical_pair("u1", "i2")
        key = "workspace:v1.2.2:u1:i2"
        self.assertEqual(pair.canonical_key, key)
        self.assertEqual(pair.canonical_sha256, hashlib.sha256(key.encode()).hexdigest())
        self.assertTrue(pair.runnable)

    def test_pair_rejects_mismatched_key_or_hash(self) -> None:
        pair = canonical_pair("u1", "i2")
        key_data = pair.model_dump()
        key_data["canonical_key"] = "workspace:v1.2.2:u1:wrong"
        with self.assertRaisesRegex(ValidationError, "canonical_key"):
            AgentDojoPair.model_validate(key_data)
        hash_data = pair.model_dump()
        hash_data["canonical_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValidationError, "canonical_sha256"):
            AgentDojoPair.model_validate(hash_data)

    def test_selection_is_order_independent_and_uses_three_passes(self) -> None:
        candidates = [
            canonical_pair("u1", "i1"),
            canonical_pair("u2", "i1"),
            canonical_pair("u3", "i3"),
            canonical_pair("u4", "i4"),
            canonical_pair("u5", "i5"),
            canonical_pair("u6", "i6"),
            canonical_pair("u7", "i7"),
            canonical_pair("u8", "i8"),
            canonical_pair("u9", "i9"),
            canonical_pair("u10", "i10"),
            canonical_pair("u11", "i11"),
            canonical_pair("u12", "i12"),
            canonical_pair("u13", "i13"),
            canonical_pair("u14", "i14"),
            canonical_pair("u15", "i15"),
            canonical_pair("u16", "i16"),
            canonical_pair("u17", "i17"),
            canonical_pair("u18", "i18"),
            canonical_pair("u19", "i19"),
            canonical_pair("u20", "i20"),
        ]
        selected = select_agentdojo_pairs(candidates)
        shuffled = select_agentdojo_pairs(list(reversed(candidates)))
        self.assertEqual([item.canonical_key for item in selected], [item.canonical_key for item in shuffled])
        self.assertEqual(len(selected), 18)
        self.assertEqual(len({item.user_task_id for item in selected[:2]}), 2)
        self.assertEqual(len({item.injection_task_id for item in selected[:2]}), 2)

    def test_selection_requires_eighteen_runnable_pairs(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 18 runnable AgentDojo pairs are required"):
            select_agentdojo_pairs(_candidates(17))

    def test_selection_rejects_duplicate_canonical_pairs(self) -> None:
        candidates = _candidates(18)
        candidates.append(candidates[0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            select_agentdojo_pairs(candidates)

    def test_matrix_counts_and_unique_run_ids(self) -> None:
        selected = select_agentdojo_pairs(_candidates(24))
        development, formal = selected[:2], selected[2:]
        development_plan = build_development_plan(development, _MODEL_HASH)
        formal_plan = build_formal_plan(formal, _MODEL_HASH)
        formal_attacked = [row for row in formal_plan if row.attack != "none"]
        formal_clean = [row for row in formal_plan if row.attack == "none"]
        self.assertEqual(len(formal_attacked), 64)
        self.assertLessEqual(len(formal_clean), 32)
        self.assertLessEqual(len(formal_attacked) + len(formal_clean), 96)
        self.assertEqual({row.attack for row in formal_attacked}, {"important_instructions", "tool_knowledge"})
        self.assertEqual({row.defense for row in formal_attacked}, {"none", "repeat_user_prompt"})
        self.assertEqual({row.attack for row in formal_clean}, {"none"})
        self.assertEqual({row.model_config_hash for row in (*development_plan, *formal_plan)}, {_MODEL_HASH})
        all_rows = (*development_plan, *formal_plan)
        self.assertEqual(len({row.run_id for row in all_rows}), len(all_rows))
        self.assertEqual({row.phase for row in development_plan}, {"development"})
        self.assertEqual({row.phase for row in formal_plan}, {"formal"})

    def test_builders_require_exact_partition_sizes(self) -> None:
        selected = select_agentdojo_pairs(_candidates(24))
        with self.assertRaisesRegex(ValueError, "exactly 2"):
            build_development_plan(selected[:1], _MODEL_HASH)
        with self.assertRaisesRegex(ValueError, "exactly 16"):
            build_formal_plan(selected[:15], _MODEL_HASH)

    def test_formal_validator_rejects_duplicate_missing_added_and_model_drift(self) -> None:
        selected = select_agentdojo_pairs(_candidates(24))
        formal = selected[2:]
        rows = build_formal_plan(formal, _MODEL_HASH)
        with self.assertRaises(TypeError):
            validate_agentdojo_plan(rows, formal, _MODEL_HASH)
        validate_agentdojo_plan(
            rows,
            formal,
            _MODEL_HASH,
            served_model_name=_MODEL_NAME,
            model_checkpoint_path=_MODEL_PATH,
            model_checkpoint_sha256=_CHECKPOINT_HASH,
        )
        manifest = AgentDojoFrozenManifest(**_valid_manifest_fields())
        with self.assertRaises(TypeError):
            validate_agentdojo_plan(rows, formal, _MODEL_HASH, manifest=manifest)
        validate_agentdojo_plan(
            rows,
            formal,
            _MODEL_HASH,
            manifest=manifest,
            served_model_name=_MODEL_NAME,
            model_checkpoint_path=_MODEL_PATH,
            model_checkpoint_sha256=_CHECKPOINT_HASH,
        )
        with self.assertRaisesRegex(ValueError, "model_checkpoint_path"):
            validate_agentdojo_plan(
                rows,
                formal,
                _MODEL_HASH,
                manifest=manifest,
                served_model_name=_MODEL_NAME,
                model_checkpoint_path="/tmp/drifted-checkpoint",
                model_checkpoint_sha256=_CHECKPOINT_HASH,
            )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_agentdojo_plan([*rows, rows[0]], formal, _MODEL_HASH, manifest=manifest, served_model_name=_MODEL_NAME, model_checkpoint_path=_MODEL_PATH, model_checkpoint_sha256=_CHECKPOINT_HASH)
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_agentdojo_plan(rows[:-1], formal, _MODEL_HASH, manifest=manifest, served_model_name=_MODEL_NAME, model_checkpoint_path=_MODEL_PATH, model_checkpoint_sha256=_CHECKPOINT_HASH)
        added = AgentDojoRunSpec(
            phase="formal",
            user_task_id=formal[0].user_task_id,
            injection_task_id="not-a-selected-injection",
            attack="important_instructions",
            defense="none",
            model_config_hash=_MODEL_HASH,
        )
        with self.assertRaisesRegex(ValueError, "unexpected|added|selected"):
            validate_agentdojo_plan([*rows, added], formal, _MODEL_HASH, manifest=manifest, served_model_name=_MODEL_NAME, model_checkpoint_path=_MODEL_PATH, model_checkpoint_sha256=_CHECKPOINT_HASH)
        drifted = rows[0].model_dump()
        drifted["model_config_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "model_config_hash"):
            validate_agentdojo_plan([drifted, *rows[1:]], formal, _MODEL_HASH, manifest=manifest, served_model_name=_MODEL_NAME, model_checkpoint_path=_MODEL_PATH, model_checkpoint_sha256=_CHECKPOINT_HASH)


    def test_result_record_preserves_official_security_semantics(self) -> None:
        attacked = AgentDojoResultRecord(
            phase="formal",
            user_task_id="u",
            injection_task_id="i",
            attack="important_instructions",
            defense="none",
            model_config_hash=_MODEL_HASH,
            run_id="run-native",
            attempt_id="attempt-0001",
            valid=True,
            utility=True,
            targeted_attack_success=False,
            official_security_value=False,
        )
        self.assertFalse(attacked.targeted_attack_success)
        self.assertFalse(attacked.security)
        clean = AgentDojoResultRecord(
            phase="formal",
            user_task_id="u",
            injection_task_id=None,
            attack="none",
            defense="none",
            model_config_hash=_MODEL_HASH,
            run_id="run-clean",
            attempt_id="attempt-0001",
            valid=True,
            utility=True,
        )
        self.assertIsNone(clean.targeted_attack_success)
        with self.assertRaises(ValidationError):
            mismatch = attacked.model_dump()
            mismatch["targeted_attack_success"] = True
            AgentDojoResultRecord(**mismatch)

    def test_strict_frozen_models_reject_unknown_fields_and_are_immutable(self) -> None:
        pair = canonical_pair("u", "i")
        pair_data = pair.model_dump()
        pair_data["unexpected"] = True
        with self.assertRaises(ValidationError):
            AgentDojoPair.model_validate(pair_data)
        row = AgentDojoRunSpec(
            phase="formal",
            user_task_id="u",
            injection_task_id=None,
            attack="none",
            defense="none",
            model_config_hash=_MODEL_HASH,
        )
        self.assertTrue(row.run_id.startswith("adj-"))
        with self.assertRaises(ValidationError):
            row.attack = "tool_knowledge"

    def test_manifest_requires_exact_partition_and_model_identity(self) -> None:
        manifest = AgentDojoFrozenManifest(**_valid_manifest_fields())
        self.assertEqual(manifest.schema_version, "1")
        self.assertEqual(manifest.selected_pair_count, 18)
        self.assertEqual(manifest.formal_total_count, 64 + manifest.formal_clean_count)
        wrong_count = _valid_manifest_fields()
        wrong_count["selected_pair_count"] = 17
        with self.assertRaisesRegex(ValidationError, "exactly 18"):
            AgentDojoFrozenManifest(**wrong_count)
        overlap = _valid_manifest_fields()
        overlap["development_pair_ids"] = tuple(overlap["formal_pair_ids"][:1]) + tuple(overlap["development_pair_ids"][1:])
        with self.assertRaisesRegex(ValidationError, "disjoint|partition"):
            AgentDojoFrozenManifest(**overlap)
        reordered = _valid_manifest_fields()
        reordered["selected_pair_ids"] = tuple(reordered["selected_pair_ids"][1:2]) + tuple(reordered["selected_pair_ids"][0:1]) + tuple(reordered["selected_pair_ids"][2:])
        with self.assertRaisesRegex(ValidationError, "first two|formal partition"):
            AgentDojoFrozenManifest(**reordered)
        unknown = _valid_manifest_fields()
        unknown_key = canonical_pair("unknown-user", "unknown-injection").canonical_key
        unknown["formal_pair_ids"] = tuple(unknown["formal_pair_ids"][:-1]) + (unknown_key,)
        with self.assertRaisesRegex(ValidationError, "partition|selected"):
            AgentDojoFrozenManifest(**unknown)
        invalid_hash = _valid_manifest_fields()
        invalid_hash["model_config_hash"] = "not-a-sha256"
        with self.assertRaises(ValidationError):
            AgentDojoFrozenManifest(**invalid_hash)
        validate_agentdojo_model_binding(
            manifest,
            _MODEL_HASH,
            _MODEL_NAME,
            _MODEL_PATH,
            _CHECKPOINT_HASH,
        )
        with self.assertRaisesRegex(ValueError, "model_config_hash"):
            validate_agentdojo_model_binding(manifest, "f" * 64, _MODEL_NAME, manifest.model_checkpoint_path, _CHECKPOINT_HASH)
        with self.assertRaisesRegex(ValueError, "served_model_name"):
            validate_agentdojo_model_binding(manifest, _MODEL_HASH, "other-model", manifest.model_checkpoint_path, _CHECKPOINT_HASH)
        no_checkpoint = _valid_manifest_fields()
        no_checkpoint["model_checkpoint_path"] = "relative/model"
        with self.assertRaises(ValidationError):
            AgentDojoFrozenManifest(**no_checkpoint)
        malformed = _valid_manifest_fields()
        malformed["selected_pair_ids"] = ("workspace:v1.2.2::injection",) + tuple(malformed["selected_pair_ids"][1:])
        with self.assertRaisesRegex(ValidationError, "nonempty"):
            AgentDojoFrozenManifest(**malformed)
        malformed = _valid_manifest_fields()
        malformed["selected_pair_ids"] = ("workspace:v1.2.2:user:",) + tuple(malformed["selected_pair_ids"][1:])
        with self.assertRaisesRegex(ValidationError, "nonempty"):
            AgentDojoFrozenManifest(**malformed)
        with self.assertRaisesRegex(ValueError, "model_checkpoint_sha256"):
            validate_agentdojo_model_binding(manifest, _MODEL_HASH, _MODEL_NAME, _MODEL_PATH, "a" * 64)


    def test_freeze_cli_writes_hashed_artifacts_and_is_exclusive(self) -> None:
        from scripts.freeze_agentdojo_external import freeze_slice, verify_slice

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            (checkpoint / "config.json").write_text("{}\n", encoding="utf-8")
            config_path = root / "config.json"
            config_path.write_text(json.dumps({
                "agentdojo_commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
                "agentdojo_tag": "v0.1.35",
                "attacks": ["important_instructions", "tool_knowledge"],
                "benchmark_version": "v1.2.2",
                "defenses": ["none", "repeat_user_prompt"],
                "model_display_name": "Qwen",
                "model_path": str(checkpoint),
                "served_model_name": "qwen3-vl-8b",
                "suite": "workspace",
                "temperature": 0.0,
                "tool_output_format": "json",
            }), encoding="utf-8")
            candidates = _candidates(24)
            screening = [{
                "canonical_key": pair.canonical_key,
                "canonical_sha256": pair.canonical_sha256,
                "user_task_id": pair.user_task_id,
                "injection_task_id": pair.injection_task_id,
                "runnable": pair.runnable,
                "exclusion_reason": pair.exclusion_reason,
                "attacks": {
                    "important_instructions": {"nonempty": True},
                    "tool_knowledge": {"nonempty": True},
                },
            } for pair in candidates]

            def fake_enumerator(*_args: object) -> tuple[list[AgentDojoPair], list[dict[str, object]]]:
                return candidates, screening

            # The production contract binds the exact approved checkpoint; use a
            # temporary fixture by patching that constant only inside this unit test.
            with (
                patch("scripts.freeze_agentdojo_external._agentdojo_version", return_value="0.1.35"),
                patch("scripts.freeze_agentdojo_external.EXPECTED_CHECKPOINT_PATH", str(checkpoint)),
                patch("socket.create_connection", side_effect=AssertionError("freeze must not open a socket")),
            ):
                summary = freeze_slice(config_path, root / "frozen", enumerator=fake_enumerator)
                self.assertEqual(summary["selected_pair_count"], 18)
                self.assertEqual(summary["development_pair_count"], 2)
                self.assertEqual(summary["formal_pair_count"], 16)
                self.assertLessEqual(summary["formal_total_count"], 96)
                self.assertTrue(verify_slice(root / "frozen", config_path)["verified"])
                with self.assertRaises(FileExistsError):
                    freeze_slice(config_path, root / "frozen", enumerator=fake_enumerator)
            manifest = json.loads((root / "frozen" / "manifest.json").read_text(encoding="utf-8"))
            for field in ("screening_sha256", "selected_pairs_sha256", "environment_sha256"):
                self.assertRegex(manifest[field], r"^[0-9a-f]{64}$")

    def test_freeze_persists_screening_exclusions_and_rejects_config_drift(self) -> None:
        from scripts.freeze_agentdojo_external import _validate_config, freeze_slice

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            (checkpoint / "config.json").write_text("{}\n", encoding="utf-8")
            config = {
                "agentdojo_commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
                "agentdojo_tag": "v0.1.35", "attacks": ["important_instructions", "tool_knowledge"],
                "benchmark_version": "v1.2.2", "defenses": ["none", "repeat_user_prompt"],
                "model_display_name": "Qwen", "model_path": str(checkpoint),
                "served_model_name": "qwen3-vl-8b", "suite": "workspace",
                "temperature": 0.0, "tool_output_format": "json",
            }
            for key, bad in (("temperature", 0.2), ("tool_output_format", "text"), ("attacks", ["tool_knowledge"]), ("served_model_name", "other")):
                mutated = dict(config); mutated[key] = bad
                with self.assertRaises(ValueError):
                    with patch("scripts.freeze_agentdojo_external.EXPECTED_CHECKPOINT_PATH", str(checkpoint)):
                        _validate_config(mutated)
            candidates = _candidates(24)
            excluded = candidates[-1].model_copy(update={"runnable": False, "exclusion_reason": "tool_knowledge: empty injection dictionary"})
            candidates[-1] = excluded
            screening = [{
                "canonical_key": pair.canonical_key, "canonical_sha256": pair.canonical_sha256,
                "user_task_id": pair.user_task_id, "injection_task_id": pair.injection_task_id,
                "runnable": pair.runnable, "exclusion_reason": pair.exclusion_reason,
                "attacks": {"important_instructions": {"nonempty": pair.runnable}, "tool_knowledge": {"nonempty": pair.runnable}},
            } for pair in candidates]
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch("scripts.freeze_agentdojo_external.EXPECTED_CHECKPOINT_PATH", str(checkpoint)),
                patch("socket.create_connection", side_effect=AssertionError("freeze must not open a socket")),
            ):
                summary = freeze_slice(config_path, root / "frozen", enumerator=lambda *_: (candidates, screening))
            self.assertEqual(summary["screened_pair_count"], 24)
            screening_rows = [json.loads(line) for line in (root / "frozen" / "screening.jsonl").read_text().splitlines()]
            excluded_rows = [row for row in screening_rows if not row["runnable"]]
            self.assertEqual(len(excluded_rows), 1)
            self.assertIn("empty injection dictionary", excluded_rows[0]["exclusion_reason"])

    def test_checkpoint_fingerprint_is_recursive_and_mtime_independent(self) -> None:
        from scripts.freeze_agentdojo_external import checkpoint_fingerprint

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nested").mkdir()
            (root / "b").write_bytes(b"b")
            (root / "nested" / "a").write_bytes(b"a")
            first = checkpoint_fingerprint(root)
            (root / "nested" / "a").touch()
            self.assertEqual(first, checkpoint_fingerprint(root))
            (root / "nested" / "a").write_bytes(b"changed")
            self.assertNotEqual(first, checkpoint_fingerprint(root))

    def test_official_attack_compatibility_registration_when_installed(self) -> None:
        try:
            from agentdojo.agent_pipeline import AgentPipeline
            from agentdojo.attacks import load_attack
            from agentdojo.models import MODEL_NAMES
            from agentdojo.task_suite import get_suite
        except ModuleNotFoundError:
            self.skipTest("AgentDojo is available only in the isolated benchmark environment")
        suite = get_suite("v1.2.2", "workspace")
        pipeline = AgentPipeline([])
        pipeline.name = "qwen3-vl-8b"
        MODEL_NAMES["qwen3-vl-8b"] = "Qwen"
        self.assertIsNotNone(load_attack("important_instructions", suite, pipeline))
        self.assertIsNotNone(load_attack("tool_knowledge", suite, pipeline))

if __name__ == "__main__":
    unittest.main()
