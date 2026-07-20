#!/usr/bin/env python3
"""Freeze the 54-cell capability-plus-provenance contrast plan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agentsec.redteam import load_frozen_scenarios, verify_frozen_corpus  # noqa: E402
from agentsec.runplan import (  # noqa: E402
    CAPABILITY_PROVENANCE_DEFENSE_ARMS,
    build_capability_provenance_plan,
    freeze_formal_plan,
    sha256_file,
)
from agentsec.schemas import stable_model_hash  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-config", type=Path, default=Path("configs/model.json"))
    parser.add_argument("--project-root", type=Path, default=Path("."))
    args = parser.parse_args()

    verify_frozen_corpus(args.corpus_dir)
    scenarios = load_frozen_scenarios(args.corpus_dir)
    model_config = json.loads(args.model_config.read_text(encoding="utf-8"))
    records = build_capability_provenance_plan(scenarios, model_config)
    inputs = [args.model_config]
    inputs.extend(sorted((args.project_root / "configs" / "prompts").glob("*.txt")))
    inputs.extend(sorted((args.corpus_dir / "scenarios").glob("*.json")))
    input_hashes = {
        path.resolve().relative_to(args.project_root.resolve()).as_posix(): sha256_file(path)
        for path in inputs
    }
    manifest = freeze_formal_plan(
        args.output_dir,
        records,
        model_config_hash=stable_model_hash(model_config),
        corpus_manifest_sha256=sha256_file(args.corpus_dir / "manifest.json"),
        input_sha256=input_hashes,
        plan_kind="capability_provenance_ablation",
        defense_arms=CAPABILITY_PROVENANCE_DEFENSE_ARMS,
    )
    print(json.dumps(manifest.model_dump(mode="json"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
