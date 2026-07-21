#!/usr/bin/env python3
"""Analyze the original and hardened corpora as separate complete factorials."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agentsec.analysis import analyze_artifacts  # noqa: E402
from agentsec.runplan import verify_frozen_plan  # noqa: E402


def _analyze_group(
    *,
    name: str,
    artifact_roots: tuple[Path, ...],
    plan_dirs: tuple[Path, ...],
    output_dir: Path,
) -> dict[str, object]:
    expected_records = []
    manifests = []
    for plan_dir in plan_dirs:
        manifest, records = verify_frozen_plan(plan_dir)
        manifests.append(manifest)
        expected_records.extend(records)
    if len({record.run_id for record in expected_records}) != len(expected_records):
        raise ValueError(f"{name} plan set contains duplicate run IDs")
    report = analyze_artifacts(
        artifact_roots,
        output_dir,
        expected_run_specs=tuple(expected_records),
        generate_plots=True,
    )
    return {
        "name": name,
        "artifact_roots": [path.as_posix() for path in artifact_roots],
        "plan_dirs": [path.as_posix() for path in plan_dirs],
        "plan_record_count": len(expected_records),
        "plan_kinds": [manifest.plan_kind for manifest in manifests],
        "report": report.model_dump(mode="json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()
    if args.no_plots:
        raise SystemExit("complete factorial publication analysis requires plots")

    root = args.project_root.resolve()
    original = _analyze_group(
        name="original",
        artifact_roots=(
            root / "artifacts/formal-v1",
            root / "artifacts/ablation-v1",
            root / "artifacts/capability-provenance-v1",
            root / "artifacts/original-provenance-completion-v1",
        ),
        plan_dirs=(
            root / "configs/frozen/formal_plan_v1",
            root / "configs/frozen/ablation_plan_v1",
            root / "configs/frozen/capability_provenance_plan_v1",
            root / "configs/frozen/original_provenance_completion_v1",
        ),
        output_dir=root / "artifacts/original-full-factorial-analysis-v1",
    )
    hardened = _analyze_group(
        name="hardened",
        artifact_roots=(
            root / "artifacts/hardened-v1",
            root / "artifacts/hardened-missing-baseline-v1",
            root / "artifacts/hardened-missing-capability-v1",
            root / "artifacts/hardened-missing-provenance-prompt-v1",
        ),
        plan_dirs=(
            root / "configs/frozen/hardened_plan_v1",
            root / "configs/frozen/hardened_missing_baseline_v1",
            root / "configs/frozen/hardened_missing_capability_v1",
            root / "configs/frozen/hardened_missing_provenance_prompt_v1",
        ),
        output_dir=root / "artifacts/hardened-full-factorial-analysis-v1",
    )
    print(json.dumps({"original": original, "hardened": hardened}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
