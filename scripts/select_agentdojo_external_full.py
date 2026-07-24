#!/usr/bin/env python3
"""Select formal attempts across all pinned native AgentDojo suites."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentsec.agentdojo_external import AGENTDOJO_SUITES, AgentDojoRunSpec  # noqa: E402
from agentsec.attempts import (  # noqa: E402
    AttemptSelectionManifest,
    build_attempt_selection,
    record_sha256,
    write_manifest_exclusive,
)


def _plan_path(plan_root: Path, suite: str) -> Path:
    path = plan_root / suite / "formal_plan.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"missing formal plan for suite {suite}: {path}")
    return path


def _aggregate_plan_sha256(plan_root: str | Path) -> tuple[str, dict[str, str]]:
    root = Path(plan_root)
    hashes = {suite: record_sha256(_plan_path(root, suite)) for suite in AGENTDOJO_SUITES}
    payload = "".join(f"{suite}\t{hashes[suite]}\n" for suite in AGENTDOJO_SUITES).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), hashes


def aggregate_plan_sha256(plan_root: str | Path) -> str:
    """Return the deterministic hash binding all suite plan bytes."""

    return _aggregate_plan_sha256(plan_root)[0]


def _suite_artifact_root(artifact_root: Path, suite: str) -> Path:
    candidate = artifact_root / suite
    if (candidate / "runs").is_dir():
        return candidate / "runs"
    if candidate.is_dir():
        return candidate
    # Backwards-compatible convenience for a one-suite fixture.  A full
    # aggregate still requires all four suite plans, so this is safe only when
    # the suite directory itself is absent and the caller supplied a shared
    # root containing that suite's run IDs.
    if suite == "workspace" and (artifact_root / "runs").is_dir():
        return artifact_root / "runs"
    return candidate


def select_full_attempts(
    plan_root: str | Path,
    artifact_root: str | Path,
    output_path: str | Path,
    *,
    scheduler_interruptions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Select one initial/recovery attempt for every formal suite row.

    Each suite is selected independently, then rows are merged into one
    top-level :class:`AttemptSelectionManifest` bound to an aggregate hash of
    the four exact plan files.  The manifest is written with exclusive create
    semantics, so an existing selection cannot be silently replaced.
    """

    plan_root = Path(plan_root)
    artifact_root = Path(artifact_root)
    aggregate_hash, suite_hashes = _aggregate_plan_sha256(plan_root)
    selections = []
    suite_counts: dict[str, int] = {}
    for suite in AGENTDOJO_SUITES:
        plan_path = _plan_path(plan_root, suite)
        rows = [
            AgentDojoRunSpec.model_validate(json.loads(line))
            for line in plan_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not rows or any(row.phase != "formal" or row.suite != suite for row in rows):
            raise ValueError(f"formal plan for {suite} must contain only formal {suite} rows")
        manifest = build_attempt_selection(
            plan_path,
            _suite_artifact_root(artifact_root, suite),
            interruptions=scheduler_interruptions,
            allow_extra_runs=True,
        )
        selections.extend(manifest.rows)
        suite_counts[suite] = len(manifest.rows)
    run_ids = [row.run_id for row in selections]
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("duplicate run IDs across AgentDojo suites")
    merged = AttemptSelectionManifest(
        plan_sha256=aggregate_hash,
        rows=tuple(sorted(selections, key=lambda row: row.run_id)),
    )
    write_manifest_exclusive(merged, output_path)
    return {
        "schema_version": merged.schema_version,
        "plan_sha256": merged.plan_sha256,
        "suite_plan_sha256": suite_hashes,
        "suite_counts": suite_counts,
        "suite_count": len(AGENTDOJO_SUITES),
        "row_count": len(merged.rows),
        "selected_count": sum(row.selected_attempt is not None for row in merged.rows),
        "output": str(Path(output_path).resolve()),
    }


def _load_interruptions(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and "runs" in value:
        value = value["runs"]
    if isinstance(value, list):
        converted: dict[str, Any] = {}
        for item in value:
            if not isinstance(item, dict) or not item.get("run_id"):
                raise ValueError("scheduler interruption rows require run_id")
            run_id = str(item["run_id"])
            if run_id in converted:
                raise ValueError(f"duplicate scheduler interruption run_id: {run_id}")
            converted[run_id] = item
        return converted
    if not isinstance(value, dict):
        raise ValueError("scheduler interruption JSON must be an object keyed by run_id")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--scheduler-interruptions", "--interruptions", dest="interruptions", type=Path)
    parser.add_argument("--output", "--output-path", dest="output", type=Path, required=True)
    args = parser.parse_args(argv)
    interruptions = _load_interruptions(args.interruptions)
    print(json.dumps(select_full_attempts(args.plan_root, args.artifact_root, args.output, scheduler_interruptions=interruptions), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
