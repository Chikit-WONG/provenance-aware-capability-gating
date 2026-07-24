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
        self.assertIn("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy", launcher)
        self.assertIn("NO_PROXY=127.0.0.1,localhost,::1", launcher)
        self.assertIn("TRANSFORMERS_OFFLINE=1", launcher)
        self.assertIn("Qwen3-VL-8B-Instruct", launcher)
        self.assertIn("select_vllm_port.sh", launcher)
        self.assertIn("launch_vllm.sh", launcher)
        self.assertIn("agentdojo-external", launcher)
        self.assertIn("/v1/models", launcher)
        self.assertIn("seq 1 600", launcher)
        self.assertIn("kill -0 \"${VLLM_PID}\"", launcher)
        self.assertIn("run_agentdojo_external.py", launcher)
        self.assertIn("AGENTDOJO_PROJECT_ROOT", launcher)
        self.assertNotRegex(launcher, r"(?im)\bgit\s+clone\b")
        self.assertNotRegex(launcher, r"(?im)\bhf\s+download\b")
        self.assertNotRegex(launcher, r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY)\s*=")

    def test_slurm_output_and_error_paths_are_absolute_artifact_paths(self) -> None:
        launcher = Path("scripts/run_agentdojo_external.slurm").read_text(encoding="utf-8")
        artifact_prefix = (
            "/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/"
            "Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/"
            "Group_Project/provenance-aware-capability-gating/"
            "artifacts/agentdojo-external-v1/slurm/"
        )
        self.assertIn(
            f"#SBATCH --output={artifact_prefix}%x-%A_%a.out",
            launcher,
        )
        self.assertIn(
            f"#SBATCH --error={artifact_prefix}%x-%A_%a.err",
            launcher,
        )

    def test_wave_submitter_is_bounded_and_uses_verified_plan_counts(self) -> None:
        submitter = Path("scripts/submit_agentdojo_external_wave.sh").read_text(encoding="utf-8")
        self.assertIn("--array=", submitter)
        self.assertRegex(submitter, r"--array=.*%2")
        self.assertIn("MAX_WAVE_TASKS=10", submitter)
        self.assertIn("MAX_FORMAL_SHARD_ROWS=8", submitter)
        self.assertIn("SHARD_START", submitter)
        self.assertIn("WAVE_SHARDS", submitter)
        self.assertIn("formal_plan.jsonl", submitter)
        self.assertIn("ARRAY_END=$((SHARD_START + TASKS_IN_WAVE - 1))", submitter)
        self.assertIn("AGENTDOJO_FROZEN_ROOT=", submitter)
        self.assertIn("mkdir -p \"${SLURM_LOG_DIR}\"", submitter)
        self.assertNotIn("lower shard limit", submitter)
        self.assertIn("development", submitter)
        self.assertNotRegex(submitter, r"\b96\b")

    def test_slurm_array_tasks_use_deterministic_ports_and_unique_logs(self) -> None:
        launcher = Path("scripts/run_agentdojo_external.slurm").read_text(encoding="utf-8")
        self.assertIn('VLLM_PORT_STRIDE="${VLLM_PORT_STRIDE:-10}"', launcher)
        self.assertIn('SLURM_ARRAY_TASK_ID', launcher)
        self.assertIn('PORT_BASE=$((BASE_PORT + SLURM_ARRAY_TASK_ID * VLLM_PORT_STRIDE))', launcher)
        self.assertIn('SLURM_ARRAY_JOB_ID', launcher)
        self.assertIn('JOB_TOKEN', launcher)

    def test_vllm_launcher_uses_configurable_16k_context_by_default(self) -> None:
        launcher = Path("scripts/launch_vllm.sh").read_text(encoding="utf-8")
        self.assertIn('VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-16384}"', launcher)
        self.assertIn('--max-model-len "${VLLM_MAX_MODEL_LEN}"', launcher)

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


    def test_full_launcher_and_runner_are_suite_aware(self) -> None:
        runner = Path("scripts/run_agentdojo_external.py").read_text(encoding="utf-8")
        launcher = Path("scripts/run_agentdojo_external.slurm").read_text(encoding="utf-8")
        wrapper = Path("scripts/submit_agentdojo_external_full_wave.sh").read_text(encoding="utf-8")
        self.assertIn("suite_name: str = \"workspace\"", runner)
        self.assertIn("row.suite", runner)
        self.assertIn("SUITE=\"${5:-${AGENTDOJO_SUITE:-}}\"", launcher)
        self.assertIn('"${FROZEN_ROOT}/${SUITE}/${PLAN_NAME}"', launcher)
        for suite in ("workspace", "travel", "banking", "slack"):
            self.assertIn(suite, wrapper)
        self.assertIn("agentdojo-external-full-v1", wrapper)
    def test_full_selection_and_analysis_are_aggregate_suite_aware(self) -> None:
        selector = Path("scripts/select_agentdojo_external_full.py").read_text(encoding="utf-8")
        analysis = Path("scripts/analyze_agentdojo_external.py").read_text(encoding="utf-8")
        self.assertIn("def select_full_attempts", selector)
        self.assertIn("AGENTDOJO_SUITES", selector)
        self.assertIn("write_manifest_exclusive", selector)
        self.assertIn("--plan-root", analysis)
        self.assertIn("path / row.suite", analysis)
        self.assertIn("aggregate", analysis)

if __name__ == "__main__":
    unittest.main()
