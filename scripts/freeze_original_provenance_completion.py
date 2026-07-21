#!/usr/bin/env python3
"""Freeze the original-corpus 108-cell provenance completion plan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agentsec.redteam import load_frozen_scenarios, verify_frozen_corpus  # noqa: E402
from agentsec.runplan import (  # noqa: E402
    ORIGINAL_PROVENANCE_COMPLETION_DEFENSE_ARMS,
    build_original_provenance_completion_plan,
    freeze_formal_plan,
    sha256_file,
)
from agentsec.schemas import stable_model_hash  # noqa: E402


def _input_hashes(
    *, project_root: Path, corpus_dir: Path, model_config: Path
) -> dict[str, str]:
    inputs = [model_config]
    inputs.extend(
        project_root / "configs" / "prompts" / name
        for name in (
            "action_system.txt",
            "prompt_only_defense.txt",
            "reader_system.txt",
            "red_agent_system.txt",
        )
    )
    inputs.extend(sorted((corpus_dir / "scenarios").glob("*.json")))
    return {
        path.resolve().relative_to(project_root.resolve()).as_posix(): sha256_file(path)
        for path in inputs
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=PROJECT_ROOT / "data/frozen/red_corpus_qwen3_v1",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "configs/frozen/original_provenance_completion_v1",
    )
    parser.add_argument(
        "--model-config",
        type=Path,
        default=PROJECT_ROOT / "configs/model.json",
    )
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    corpus_dir = args.corpus_dir.resolve()
    model_config_path = args.model_config.resolve()
    verify_frozen_corpus(corpus_dir)
    scenarios = load_frozen_scenarios(corpus_dir)
    model_config = json.loads(model_config_path.read_text(encoding="utf-8"))
    records = build_original_provenance_completion_plan(scenarios, model_config)
    manifest = freeze_formal_plan(
        args.output_dir,
        records,
        model_config_hash=stable_model_hash(model_config),
        corpus_manifest_sha256=sha256_file(corpus_dir / "manifest.json"),
        input_sha256=_input_hashes(
            project_root=project_root,
            corpus_dir=corpus_dir,
            model_config=model_config_path,
        ),
        plan_kind="original_provenance_completion",
        defense_arms=ORIGINAL_PROVENANCE_COMPLETION_DEFENSE_ARMS,
    )
    print(json.dumps(manifest.model_dump(mode="json"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
