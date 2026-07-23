import json
import unittest
from pathlib import Path


class AgentDojoExternalConfigTests(unittest.TestCase):
    def test_config_pins_public_benchmark_and_local_victim(self) -> None:
        config = json.loads(
            Path("configs/external/agentdojo_external_v1.json").read_text()
        )
        self.assertEqual(config["agentdojo_commit"], "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b")
        self.assertEqual(config["agentdojo_tag"], "v0.1.35")
        self.assertEqual(config["benchmark_version"], "v1.2.2")
        self.assertEqual(config["suite"], "workspace")
        self.assertEqual(config["attacks"], ["important_instructions", "tool_knowledge"])
        self.assertEqual(config["defenses"], ["none", "repeat_user_prompt"])
        self.assertEqual(config["model_display_name"], "Qwen")
        self.assertEqual(
            config["model_path"],
            "/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct",
        )
        self.assertEqual(config["temperature"], 0.0)
        self.assertEqual(config["served_model_name"], "qwen3-vl-8b")
        self.assertTrue(Path(config["model_path"]).is_absolute())
        self.assertEqual(config["tool_output_format"], "json")


if __name__ == "__main__":
    unittest.main()
