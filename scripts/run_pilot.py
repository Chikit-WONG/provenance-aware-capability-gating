#!/usr/bin/env python3
"""Run the pre-declared development-payload pilot and evaluate its gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec.analysis import load_artifact_records
from agentsec.experiment import execute_run_plan
from agentsec.model_client import OpenAIModelClient
from agentsec.pilot import evaluate_pilot_gates, write_pilot_report
from agentsec.redteam import load_candidate_scenarios, verify_frozen_corpus
from agentsec.schemas import ContentCondition, DefenseArm, RunSpec, stable_model_hash


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--pilot-report", type=Path, required=True)
    parser.add_argument("--model-config", type=Path, default=Path("configs/model.json"))
    parser.add_argument("--base-url", help="runtime vLLM endpoint override")
    parser.add_argument("--candidate-index", type=int, default=1, choices=(1, 2, 3))
    args = parser.parse_args()

    corpus_manifest = verify_frozen_corpus(args.corpus_dir)
    scenarios = load_candidate_scenarios(
        args.corpus_dir, args.candidate_index, require_formal_eligible=True
    )
    config = json.loads(args.model_config.read_text(encoding="utf-8"))
    model_hash = stable_model_hash(config)
    if corpus_manifest.model_id != config["model"]:
        raise ValueError("pilot model differs from the frozen Red corpus model")
    # One development candidate is selected before victim runs.  Its index is
    # recorded in every repetition and cannot be changed by outcome.
    records = []
    for scenario in scenarios:
        for condition, arms in (
            (ContentCondition.CLEAN, (DefenseArm.FULL,)),
            (ContentCondition.PLACEBO, (DefenseArm.ALLOW_ALL,)),
            (ContentCondition.ATTACK, (DefenseArm.ALLOW_ALL, DefenseArm.FULL)),
        ):
            for arm in arms:
                records.append(
                    RunSpec(
                        scenario_id=scenario.scenario_id,
                        content_condition=condition,
                        defense_arm=arm,
                        seed=4313,
                        repetition=args.candidate_index - 1,
                        model_config_hash=model_hash,
                    )
                )
    options = {
        "reader_max_model_calls": int(config["reader_max_model_calls"]),
        "action_max_model_calls": int(config["action_max_model_calls"]),
        "reader_max_tokens": int(config["reader_max_tokens"]),
        "action_max_tokens": int(config["action_max_tokens"]),
        "temperature": float(config["temperature"]),
        "top_p": float(config["top_p"]),
    }
    with OpenAIModelClient(
        base_url=args.base_url or config["base_url"],
        model=config["model"],
        timeout=float(config["timeout_seconds"]),
    ) as client:
        summary = execute_run_plan(
            client,
            records,
            scenarios,
            artifact_root=args.output_root,
            payload_base_dir=args.corpus_dir,
            orchestrator_options=options,
        )
    loaded = load_artifact_records(args.output_root)
    report = evaluate_pilot_gates(loaded)
    write_pilot_report(args.pilot_report, report)
    print(json.dumps({"execution": summary.model_dump(mode="json"), "gates": report.model_dump(mode="json")}, sort_keys=True))
    return 0 if report.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
