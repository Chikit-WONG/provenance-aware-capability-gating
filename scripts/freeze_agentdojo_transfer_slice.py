#!/usr/bin/env python3
"""Freeze a balanced, suite-stratified AgentDojo transfer slice."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentsec.agentdojo_external import (  # noqa: E402
    AGENTDOJO_SUITES,
    TRANSFER_DEFENSES,
    AgentDojoRunSpec,
    build_transfer_plan_from_rows,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path: Path) -> list[AgentDojoRunSpec]:
    return [AgentDojoRunSpec.model_validate(json.loads(line)) for line in path.read_text().splitlines() if line.strip()]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def freeze(source_root: Path, output_root: Path, pairs_per_suite: int) -> dict[str, Any]:
    if pairs_per_suite < 1:
        raise ValueError("pairs_per_suite must be positive")
    if output_root.exists():
        raise FileExistsError(f"refusing to overwrite slice root: {output_root}")
    output_root.mkdir(parents=True)
    suites: dict[str, Any] = {}
    formal_total = 0
    for suite in AGENTDOJO_SUITES:
        source_path = source_root / suite / "formal_plan.jsonl"
        source_rows = _rows(source_path)
        attacked: list[tuple[str, str | None, str]] = []
        seen_attacked: set[tuple[str, str | None, str]] = set()
        for row in source_rows:
            if row.attack == "none":
                continue
            key = (row.user_task_id, row.injection_task_id, row.attack)
            if key not in seen_attacked:
                seen_attacked.add(key)
                attacked.append(key)
        selected_attacked = attacked[: pairs_per_suite * 2]
        if len(selected_attacked) < pairs_per_suite * 2:
            raise ValueError(f"{suite} has only {len(selected_attacked) // 2} complete pairs")
        selected_keys = set(selected_attacked)
        selected_users = {user for user, _injection, _attack in selected_attacked}
        selected_rows = [
            row
            for row in source_rows
            if (row.attack != "none" and (row.user_task_id, row.injection_task_id, row.attack) in selected_keys)
            or (row.attack == "none" and row.user_task_id in selected_users)
        ]
        expanded = build_transfer_plan_from_rows(selected_rows)
        output_path = output_root / suite / "formal_plan.jsonl"
        text = "\n".join(row.model_dump_json() for row in expanded) + "\n"
        _write(output_path, text)
        formal_total += len(expanded)
        suites[suite] = {
            "source_plan": str(source_path),
            "source_sha256": _sha(source_path),
            "output_plan": str(output_path),
            "output_sha256": _sha(output_path),
            "selected_attacked_cells": len(selected_attacked),
            "selected_pairs": pairs_per_suite,
            "selected_clean_users": len(selected_users),
            "output_rows": len(expanded),
        }
    manifest = {
        "schema_version": "1",
        "kind": "agentdojo_public_transfer_stratified_slice",
        "agentdojo_tag": "v0.1.35",
        "agentdojo_commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
        "benchmark_version": "v1.2.2",
        "defenses": list(TRANSFER_DEFENSES),
        "pairs_per_suite": pairs_per_suite,
        "formal_total": formal_total,
        "suites": suites,
    }
    _write(output_root / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--pairs-per-suite", type=int, default=60)
    args = parser.parse_args()
    manifest = freeze(args.source_root, args.output_root, args.pairs_per_suite)
    print(json.dumps({"formal_total": manifest["formal_total"], "pairs_per_suite": manifest["pairs_per_suite"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
