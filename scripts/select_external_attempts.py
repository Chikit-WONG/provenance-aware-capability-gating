#!/usr/bin/env python3
"""Freeze an explicit native AgentDojo attempt-selection manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentsec.attempts import build_attempt_selection, write_manifest_exclusive  # noqa: E402


def _load_interruption(path: Path | None) -> Mapping[str, Any] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, Mapping) and "runs" in value:
        value = value["runs"]
    if isinstance(value, list):
        converted = {}
        for item in value:
            if not isinstance(item, Mapping) or not item.get("run_id"):
                raise ValueError("scheduler interruption rows require run_id")
            run_id = str(item["run_id"])
            if run_id in converted:
                raise ValueError(f"duplicate scheduler interruption run_id: {run_id}")
            converted[run_id] = item
        return converted
    if not isinstance(value, Mapping):
        raise ValueError("scheduler interruption JSON must be an object keyed by run_id")
    return value


def select_attempts(
    plan_path: str | Path,
    artifact_root: str | Path,
    output_path: str | Path,
    *,
    scheduler_interruption: str | Path | None = None,
) -> dict[str, Any]:
    plan_path = Path(plan_path)
    artifact_root = Path(artifact_root)
    # The runner stores records below ``runs/``; accepting either that parent
    # or its runs directory makes the CLI unambiguous and backwards compatible.
    records_root = artifact_root / "runs" if (artifact_root / "runs").is_dir() else artifact_root
    manifest = build_attempt_selection(
        plan_path,
        records_root,
        interruptions=_load_interruption(Path(scheduler_interruption) if scheduler_interruption else None),
        # A shared root may contain the separate development gate records;
        # selection still enumerates and hashes only the requested plan rows.
        allow_extra_runs=True,
    )
    write_manifest_exclusive(manifest, output_path)
    return {
        "schema_version": manifest.schema_version,
        "plan_sha256": manifest.plan_sha256,
        "row_count": len(manifest.rows),
        "selected_count": sum(row.selected_attempt is not None for row in manifest.rows),
        "output": str(Path(output_path).resolve()),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", "--frozen-plan", dest="plan", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--scheduler-interruption", "--interruptions", dest="interruptions", type=Path)
    parser.add_argument("--output", "--output-path", dest="output", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(select_attempts(args.plan, args.artifact_root, args.output, scheduler_interruption=args.interruptions), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
