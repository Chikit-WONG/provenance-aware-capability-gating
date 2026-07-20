import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentsec.runplan import (
    ABLATION_DEFENSE_ARMS,
    CAPABILITY_PROVENANCE_DEFENSE_ARMS,
    EXPECTED_FORMAL_RUNS,
    FORMAL_DEFENSE_ARMS,
    build_ablation_plan,
    build_capability_provenance_plan,
    build_formal_plan,
    freeze_formal_plan,
    sha256_file,
    verify_frozen_plan,
)
from agentsec.scenarios import load_scenarios
from agentsec.schemas import DefenseArm, stable_model_hash


class RunPlanTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = load_scenarios()
        self.model_config = {"model": "local-test", "temperature": 0.0}

    def test_plan_is_complete_deterministic_and_shuffled(self):
        first = build_formal_plan(self.scenarios, self.model_config)
        second = build_formal_plan(self.scenarios, self.model_config)
        self.assertEqual(first, second)
        self.assertEqual(len(first), EXPECTED_FORMAL_RUNS)
        self.assertEqual(
            {row.defense_arm for row in first}, set(FORMAL_DEFENSE_ARMS)
        )
        self.assertEqual(len({row.run_id for row in first}), EXPECTED_FORMAL_RUNS)
        self.assertNotEqual(first[0].scenario_id, first[-1].scenario_id)

    def test_ablation_plan_has_only_prompt_capability_arm(self):
        records = build_ablation_plan(self.scenarios, self.model_config)

        self.assertEqual(len(records), 54)
        self.assertEqual(
            {row.defense_arm for row in records},
            {DefenseArm.PROMPT_CAPABILITY_ONLY},
        )
        self.assertEqual(
            {row.defense_arm for row in records}, set(ABLATION_DEFENSE_ARMS)
        )

    def test_capability_provenance_plan_has_only_new_arm(self):
        records = build_capability_provenance_plan(self.scenarios, self.model_config)

        self.assertEqual(len(records), 54)
        self.assertEqual(
            {row.defense_arm for row in records},
            {DefenseArm.CAPABILITY_PROVENANCE_ONLY},
        )
        self.assertEqual(
            {row.defense_arm for row in records}, set(CAPABILITY_PROVENANCE_DEFENSE_ARMS)
        )

    def test_ablation_plan_freezes_and_verifies(self):
        records = build_ablation_plan(self.scenarios, self.model_config)
        model_hash = stable_model_hash(self.model_config)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "ablation-plan"
            manifest = freeze_formal_plan(
                root,
                records,
                model_config_hash=model_hash,
                corpus_manifest_sha256="a" * 64,
                plan_kind="provenance_ablation",
                defense_arms=ABLATION_DEFENSE_ARMS,
            )

            checked, loaded = verify_frozen_plan(root)

            self.assertEqual(checked, manifest)
            self.assertEqual(checked.plan_kind, "provenance_ablation")
            self.assertEqual(checked.defense_arms, ABLATION_DEFENSE_ARMS)
            self.assertEqual(tuple(records), loaded)

    def test_manifest_rejects_plan_kind_arm_mismatch_before_writing(self):
        records = build_formal_plan(self.scenarios, self.model_config)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "mislabeled-plan"
            with self.assertRaisesRegex(ValueError, "defense arms"):
                freeze_formal_plan(
                    root,
                    records,
                    model_config_hash=stable_model_hash(self.model_config),
                    corpus_manifest_sha256="a" * 64,
                    plan_kind="provenance_ablation",
                    defense_arms=FORMAL_DEFENSE_ARMS,
                )

            self.assertFalse(root.exists())

    def test_checked_in_legacy_formal_plan_still_verifies(self):
        manifest, records = verify_frozen_plan(
            Path("configs/frozen/formal_plan_v1")
        )

        self.assertEqual(manifest.plan_kind, "formal")
        self.assertEqual(manifest.defense_arms, FORMAL_DEFENSE_ARMS)
        self.assertEqual(len(records), EXPECTED_FORMAL_RUNS)

    def test_ablation_freeze_cli_writes_verified_plan(self):
        script = Path("scripts/freeze_ablation_plan.py")
        self.assertTrue(script.stat().st_mode & stat.S_IXUSR)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "ablation-plan"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--corpus-dir",
                    "data/frozen/red_corpus_qwen3_v1",
                    "--output-dir",
                    str(root),
                    "--project-root",
                    ".",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest, records = verify_frozen_plan(root)
            self.assertEqual(manifest.plan_kind, "provenance_ablation")
            self.assertEqual(manifest.defense_arms, ABLATION_DEFENSE_ARMS)
            self.assertEqual(len(records), 54)
            legacy_manifest = json.loads(
                Path("configs/frozen/formal_plan_v1/manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                manifest.corpus_manifest_sha256,
                legacy_manifest["corpus_manifest_sha256"],
            )
            self.assertEqual(
                manifest.model_config_hash, legacy_manifest["model_config_hash"]
            )
            self.assertEqual(manifest.input_sha256, legacy_manifest["input_sha256"])

    def test_freeze_is_exclusive_and_detects_corruption(self):
        records = build_formal_plan(self.scenarios, self.model_config)
        model_hash = stable_model_hash(self.model_config)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "formal-plan"
            manifest = freeze_formal_plan(
                root,
                records,
                model_config_hash=model_hash,
                corpus_manifest_sha256="a" * 64,
            )
            checked, loaded = verify_frozen_plan(root)
            self.assertEqual(checked, manifest)
            self.assertEqual(tuple(records), loaded)
            with self.assertRaises(FileExistsError):
                freeze_formal_plan(
                    root,
                    records,
                    model_config_hash=model_hash,
                    corpus_manifest_sha256="a" * 64,
                )
            with (root / "run_plan.jsonl").open("a", encoding="utf-8") as handle:
                handle.write("{}\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_frozen_plan(root)

    def test_file_hash_matches_known_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "x.json"
            path.write_text(json.dumps({"a": 1}), encoding="utf-8")
            self.assertEqual(len(sha256_file(path)), 64)


if __name__ == "__main__":
    unittest.main()
