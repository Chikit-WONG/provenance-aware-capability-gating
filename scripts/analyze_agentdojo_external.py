#!/usr/bin/env python3
"""Analyze frozen native AgentDojo records into a publication bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentsec.agentdojo_external import AGENTDOJO_SUITES, AgentDojoResultRecord, AgentDojoRunSpec  # noqa: E402
from agentsec.attempts import AttemptSelectionManifest, record_sha256  # noqa: E402
from agentsec.agentdojo_external_analysis import validate_formal_records, write_analysis_bundle  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _aggregate_plan_hash(plan_root: Path) -> str:
    hashes: list[str] = []
    for suite in AGENTDOJO_SUITES:
        path = plan_root / suite / "formal_plan.jsonl"
        if not path.is_file():
            raise FileNotFoundError(f"missing formal plan for suite {suite}: {path}")
        digest = record_sha256(path)
        hashes.append(f"{suite}\t{digest}\n")
    return hashlib.sha256("".join(hashes).encode("utf-8")).hexdigest()


def _load_records(path: Path, plans: Sequence[AgentDojoRunSpec], selection: AttemptSelectionManifest):
    """Load selected records from a shared or suite-partitioned artifact root."""
    if not path.is_dir():
        raise ValueError("--records must be an append-only artifact root so selected record hashes can be verified")
    records: list[AgentDojoResultRecord] = []
    hashes: dict[str, str] = {}
    for row in plans:
        selected = selection.for_run(row.run_id)
        if selected.selected_attempt is None:
            raise ValueError(f"no selected attempt for {row.run_id}")
        roots = [path / row.suite, path]
        candidates: list[Path] = []
        for root in roots:
            candidates.extend(
                [
                    root / "runs" / row.run_id / selected.selected_attempt / "record.json",
                    root / row.run_id / selected.selected_attempt / "record.json",
                ]
            )
        record_path = next((candidate for candidate in candidates if candidate.is_file()), None)
        if record_path is None:
            raise FileNotFoundError(f"selected record missing for {row.run_id}")
        hashes[row.run_id] = _sha(record_path)
        records.append(AgentDojoResultRecord.model_validate(json.loads(record_path.read_text(encoding="utf-8"))))
    return records, hashes


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    plan_group = parser.add_mutually_exclusive_group(required=True)
    plan_group.add_argument("--plan", type=Path)
    plan_group.add_argument("--plan-root", type=Path)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--attempt-selection", type=Path, required=True)
    parser.add_argument("--plan-sha256", help="required for legacy single-suite analysis")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.plan_root:
        plan_paths = [args.plan_root / suite / "formal_plan.jsonl" for suite in AGENTDOJO_SUITES]
        plans = [AgentDojoRunSpec.model_validate(row) for plan_path in plan_paths for row in _rows(plan_path)]
        actual_plan_hash = _aggregate_plan_hash(args.plan_root)
    else:
        plans = [AgentDojoRunSpec.model_validate(row) for row in _rows(args.plan)]
        actual_plan_hash = _sha(args.plan)
        if args.plan_sha256 and args.plan_sha256 != actual_plan_hash:
            raise ValueError("--plan-sha256 does not match plan file bytes")

    selection = AttemptSelectionManifest.model_validate(json.loads(args.attempt_selection.read_text(encoding="utf-8")))
    if selection.plan_sha256 != actual_plan_hash:
        raise ValueError("attempt-selection plan_sha256 does not match frozen plan bytes")
    records, per_record_hashes = _load_records(args.records, plans, selection)
    validate_formal_records(records, plans, selection, actual_plan_hash, record_hashes=per_record_hashes)
    selection_hash = _sha(args.attempt_selection)
    input_hashes = {"plan": actual_plan_hash, "attempt_selection": selection_hash}
    input_hashes.update({f"record:{run_id}": digest for run_id, digest in (per_record_hashes or {}).items()})
    metadata = {"suite_count": len({row.suite for row in plans}), "suites": sorted({row.suite for row in plans})}
    result = write_analysis_bundle(
        records,
        args.output_dir,
        plan_hash=actual_plan_hash,
        attempt_selection_hash=selection_hash,
        input_record_hashes=input_hashes,
        metadata=metadata,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
