import json
import tempfile
import unittest
from pathlib import Path

from agentsec.runplan import (
    EXPECTED_FORMAL_RUNS,
    build_formal_plan,
    freeze_formal_plan,
    sha256_file,
    verify_frozen_plan,
)
from agentsec.scenarios import load_scenarios
from agentsec.schemas import stable_model_hash


class RunPlanTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = load_scenarios()
        self.model_config = {"model": "local-test", "temperature": 0.0}

    def test_plan_is_complete_deterministic_and_shuffled(self):
        first = build_formal_plan(self.scenarios, self.model_config)
        second = build_formal_plan(self.scenarios, self.model_config)
        self.assertEqual(first, second)
        self.assertEqual(len(first), EXPECTED_FORMAL_RUNS)
        self.assertEqual(len({row.run_id for row in first}), EXPECTED_FORMAL_RUNS)
        self.assertNotEqual(first[0].scenario_id, first[-1].scenario_id)

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
