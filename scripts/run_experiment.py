#!/usr/bin/env python3
"""Run a verified slice of the frozen formal plan against local vLLM."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec.experiment import execute_run_plan, load_verified_formal_inputs
from agentsec.model_client import OpenAIModelClient
from agentsec.schemas import stable_model_hash


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--model-config", type=Path, default=Path("configs/model.json"))
    parser.add_argument("--base-url", help="runtime vLLM endpoint override")
    parser.add_argument("--attempt-id", default="attempt-0001")
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    manifest, records, scenarios = load_verified_formal_inputs(
        args.plan_dir, args.corpus_dir
    )
    config = json.loads(args.model_config.read_text(encoding="utf-8"))
    if stable_model_hash(config) != manifest.model_config_hash:
        raise ValueError("runtime model config differs from the frozen run plan")
    if config.get("stream") is not False:
        raise ValueError("formal runtime requires stream=false")
    orchestrator_options = {
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
            attempt_id=args.attempt_id,
            start_index=args.start_index,
            limit=args.limit,
            resume=args.resume,
            orchestrator_options=orchestrator_options,
        )
    print(json.dumps(summary.model_dump(mode="json"), sort_keys=True))
    return 0 if summary.invalid_n == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
