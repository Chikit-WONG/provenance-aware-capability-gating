#!/usr/bin/env python3
"""Generate and atomically freeze the offline Red-Agent corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agentsec.model_client import (  # noqa: E402
    DEFAULT_BASE_URL,
    DEFAULT_MODEL_NAME,
    OpenAIModelClient,
)
from agentsec.redteam import (  # noqa: E402
    DEFAULT_SYSTEM_PROMPT,
    DeterministicRedModel,
    generate_and_freeze_red_corpus,
    load_default_red_system_prompt,
)
from agentsec.scenarios import DEFAULT_SCENARIO_DIR, load_scenarios  # noqa: E402


DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "generated" / "red_corpus_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend",
        choices=("stub", "vllm"),
        default="stub",
        help="stub is deterministic infrastructure-only data; vllm is formal eligible",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--scenario-dir", type=Path, default=DEFAULT_SCENARIO_DIR)
    parser.add_argument("--system-prompt", type=Path, default=DEFAULT_SYSTEM_PROMPT)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL_NAME)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--validation-profile",
        choices=("strict", "hardened"),
        default="strict",
        help="strict is the registered formal validator; hardened also permits only emails already in the scenario context",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scenarios = load_scenarios(args.scenario_dir)
    system_prompt = load_default_red_system_prompt(args.system_prompt)

    if args.backend == "stub":
        model_id = "deterministic-red-stub-v1"
        client = DeterministicRedModel()
        manifest = generate_and_freeze_red_corpus(
            args.output,
            scenarios,
            client,
            model_id=model_id,
            system_prompt=system_prompt,
            generator_backend="stub",
            validation_profile=args.validation_profile,
        )
        model_calls = len(client.requests)
    else:
        model_id = args.model
        with OpenAIModelClient(
            base_url=args.base_url,
            model=args.model,
            timeout=args.timeout,
        ) as client:
            manifest = generate_and_freeze_red_corpus(
                args.output,
                scenarios,
                client,
                model_id=model_id,
                system_prompt=system_prompt,
                generator_backend="vllm",
                validation_profile=args.validation_profile,
            )
        model_calls = 30

    result = {
        "ok": True,
        "output": str(args.output.resolve()),
        "backend": manifest.generator_backend,
        "formal_eligible": manifest.formal_eligible,
        "model_id": manifest.model_id,
        "model_calls": model_calls,
        "scenarios": [item.scenario_id for item in manifest.scenarios],
        "candidates_per_scenario": 5,
        "formal_candidate_index": 4,
        "reserve_candidate_index": 5,
        "validation_profile": manifest.validation_profile,
        "manifest_sha256": (args.output / "manifest.sha256")
        .read_text(encoding="ascii")
        .strip(),
    }
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
