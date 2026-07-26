import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentsec.agentdojo_external import canonical_pair
from scripts.freeze_agentdojo_external_full import freeze_full, verify_full


class FullFreezeTests(unittest.TestCase):
    def test_full_freeze_is_deterministic_and_exclusive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            (checkpoint / "config.json").write_text("{}\n", encoding="utf-8")
            config = json.loads(Path("configs/external/agentdojo_external_full_v1.json").read_text())
            config["model_path"] = str(checkpoint)
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            def enumerator(_benchmark, suite, _model):
                pairs = [canonical_pair(f"u{i}", f"i{i}", suite) for i in range(6)]
                screening = [
                    {
                        "canonical_key": pair.canonical_key,
                        "suite": suite,
                        "canonical_sha256": pair.canonical_sha256,
                        "user_task_id": pair.user_task_id,
                        "injection_task_id": pair.injection_task_id,
                        "runnable": True,
                        "exclusion_reason": "",
                        "attacks": {},
                    }
                    for pair in pairs
                ]
                return pairs, screening

            with patch("scripts.freeze_agentdojo_external_full.EXPECTED_CHECKPOINT_PATH", str(checkpoint)):
                summary = freeze_full(config_path, root / "frozen", enumerator=enumerator)
                self.assertEqual(summary["suites"], ["workspace", "travel", "banking", "slack"])
                self.assertEqual(summary["formal_total_count"], 96)
                self.assertEqual(verify_full(root / "frozen", config_path)["formal_total_count"], 96)
                with self.assertRaises(FileExistsError):
                    freeze_full(config_path, root / "frozen", enumerator=enumerator)


if __name__ == "__main__":
    unittest.main()
