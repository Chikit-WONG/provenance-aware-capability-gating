import json
import re
import unittest
from pathlib import Path


class AgentDojoExternalConfigTests(unittest.TestCase):
    def test_slurm_launcher_is_offline_debug_safe_and_local(self) -> None:
        launcher = Path("scripts/run_agentdojo_external.slurm").read_text(encoding="utf-8")
        self.assertIn("#SBATCH --partition=debug", launcher)
        self.assertIn("#SBATCH --gres=gpu:a40:1", launcher)
        self.assertIn("#SBATCH --time=00:30:00", launcher)
        cpu_match = re.search(r"#SBATCH --cpus-per-task=(\d+)", launcher)
        self.assertIsNotNone(cpu_match)
        self.assertLessEqual(int(cpu_match.group(1)), 16)
        self.assertIn("HF_HUB_OFFLINE=1", launcher)
        self.assertIn("TRANSFORMERS_OFFLINE=1", launcher)
        self.assertIn("Qwen3-VL-8B-Instruct", launcher)
        self.assertIn("select_vllm_port.sh", launcher)
        self.assertIn("launch_vllm.sh", launcher)
        self.assertIn("agentdojo-external", launcher)
        self.assertIn("/v1/models", launcher)
        self.assertIn("run_agentdojo_external.py", launcher)
        self.assertNotRegex(launcher, r"(?im)\bgit\s+clone\b")
        self.assertNotRegex(launcher, r"(?im)\bhf\s+download\b")
        self.assertNotRegex(launcher, r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY)\s*=")

    def test_wave_submitter_is_bounded_and_uses_verified_plan_counts(self) -> None:
        submitter = Path("scripts/submit_agentdojo_external_wave.sh").read_text(encoding="utf-8")
        self.assertIn("--array=", submitter)
        self.assertRegex(submitter, r"--array=.*%2")
        self.assertIn("MAX_WAVE_TASKS=10", submitter)
        self.assertIn("formal_plan.jsonl", submitter)
        self.assertRegex(submitter, r"formal.*8|8.*formal")
        self.assertIn("development", submitter)
        self.assertNotRegex(submitter, r"\b96\b")

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
