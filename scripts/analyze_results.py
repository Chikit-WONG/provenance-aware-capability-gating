#!/usr/bin/env python3
"""Validate an unambiguous artifact set and emit publication outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec.analysis import analyze_artifacts
from agentsec.runplan import verify_frozen_plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--plan-dir",
        type=Path,
        help="verified frozen formal plan; when supplied, all planned runs are required",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="omit PNG generation (JSON, CSV, and LaTeX tables are still emitted)",
    )
    args = parser.parse_args()

    expected = None
    if args.plan_dir is not None:
        _, expected = verify_frozen_plan(args.plan_dir)
    report = analyze_artifacts(
        args.artifact_root,
        args.output_dir,
        expected_run_specs=expected,
        generate_plots=not args.no_plots,
    )
    print(json.dumps(report.model_dump(mode="json"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

