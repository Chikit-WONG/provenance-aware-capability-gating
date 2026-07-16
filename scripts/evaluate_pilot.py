#!/usr/bin/env python3
"""Evaluate the fixed development-payload pilot gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec.analysis import load_artifact_records
from agentsec.pilot import evaluate_pilot_gates, write_pilot_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate pre-declared pilot gates. The artifact root must contain "
            "development-payload runs only and exactly one attempt per run ID."
        )
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    records = load_artifact_records(args.artifact_root)
    report = evaluate_pilot_gates(records)
    write_pilot_report(args.output, report)
    print(json.dumps(report.model_dump(mode="json"), sort_keys=True))
    return 0 if report.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())

