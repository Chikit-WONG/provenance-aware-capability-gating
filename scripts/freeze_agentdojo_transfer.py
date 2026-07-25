#!/usr/bin/env python3
"""Freeze a deterministic public AgentDojo transfer plan.

The source plan is never modified.  Each suite receives an append-only plan
whose cells reuse the pinned user/injection pairs and expand only the defense
dimension to the seven explicitly named transfer arms.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import sys

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
    return [
        AgentDojoRunSpec.model_validate(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_exclusive(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def freeze(source_root: Path, output_root: Path) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"refusing to overwrite transfer root: {output_root}")
    output_root.mkdir(parents=True)
    suites: dict[str, Any] = {}
    total = 0
    for suite in AGENTDOJO_SUITES:
        suite_source = source_root / suite
        suite_output = output_root / suite
        suite_output.mkdir()
        suite_info: dict[str, Any] = {}
        for phase in ("development", "formal"):
            source_plan = suite_source / f"{phase}_plan.jsonl"
            rows = _rows(source_plan)
            expanded = build_transfer_plan_from_rows(rows)
            plan_text = "\n".join(row.model_dump_json() for row in expanded) + "\n"
            output_plan = suite_output / f"{phase}_plan.jsonl"
            _write_exclusive(output_plan, plan_text)
            suite_info[phase] = {
                "source_plan": str(source_plan),
                "source_sha256": _sha(source_plan),
                "output_plan": str(output_plan),
                "output_sha256": _sha(output_plan),
                "source_rows": len(rows),
                "output_rows": len(expanded),
            }
            total += len(expanded) if phase == "formal" else 0
        suites[suite] = suite_info
    manifest = {
        "schema_version": "1",
        "kind": "agentdojo_public_transfer",
        "agentdojo_tag": "v0.1.35",
        "agentdojo_commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
        "benchmark_version": "v1.2.2",
        "defenses": list(TRANSFER_DEFENSES),
        "source_root": str(source_root),
        "suites": suites,
        "formal_total": total,
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    _write_exclusive(output_root / "manifest.json", manifest_text)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = freeze(args.source_root, args.output_root)
    print(json.dumps({"formal_total": result["formal_total"], "defenses": result["defenses"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
