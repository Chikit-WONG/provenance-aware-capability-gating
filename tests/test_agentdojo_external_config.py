import json
import unittest
from pathlib import Path


class AgentDojoExternalConfigTests(unittest.TestCase):
    def test_config_pins_public_benchmark_and_local_victim(self) -> None:
        config = json.loads(
            Path("configs/external/agentdojo_external_v1.json").read_text()
        )
        self.assertEqual(config["agentdojo_commit"], "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b")
        self.assertEqual(config["benchmark_version"], "v1.2.2")
        self.assertEqual(config["suite"], "workspace")
        self.assertEqual(config["attacks"], ["important_instructions", "tool_knowledge"])
        self.assertEqual(config["defenses"], ["none", "repeat_user_prompt"])
        self.assertEqual(config["temperature"], 0.0)
        self.assertEqual(config["served_model_name"], "qwen3-vl-8b")
        self.assertTrue(Path(config["model_path"]).is_absolute())


if __name__ == "__main__":
    unittest.main()
