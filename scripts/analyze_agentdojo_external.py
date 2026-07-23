#!/usr/bin/env python3
"""Analyze frozen native AgentDojo records into a publication bundle."""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
PROJECT_ROOT=Path(__file__).resolve().parents[1]
SRC_ROOT=PROJECT_ROOT/"src"
if str(SRC_ROOT) not in sys.path: sys.path.insert(0,str(SRC_ROOT))
from agentsec.agentdojo_external import AgentDojoRunSpec, AgentDojoResultRecord
from agentsec.attempts import AttemptSelectionManifest
from agentsec.agentdojo_external_analysis import validate_formal_records, write_analysis_bundle

def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def _rows(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _load_records(path: Path, plans, selection):
    """Load either an aggregate JSONL file or append-only run artifact root."""
    if not path.is_dir():
        return [AgentDojoResultRecord.model_validate(row) for row in _rows(path)], None
    records = []
    hashes = {}
    for row in plans:
        selected = selection.for_run(row.run_id)
        if selected.selected_attempt is None:
            raise ValueError(f"no selected attempt for {row.run_id}")
        candidates = [path / "runs" / row.run_id / selected.selected_attempt / "record.json", path / row.run_id / selected.selected_attempt / "record.json"]
        record_path = next((candidate for candidate in candidates if candidate.is_file()), None)
        if record_path is None:
            raise FileNotFoundError(f"selected record missing for {row.run_id}")
        hashes[row.run_id] = _sha(record_path)
        records.append(AgentDojoResultRecord.model_validate(json.loads(record_path.read_text(encoding="utf-8"))))
    return records, hashes

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--attempt-selection", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args=parser.parse_args(argv)
    plans=[AgentDojoRunSpec.model_validate(row) for row in _rows(args.plan)]
    selection=AttemptSelectionManifest.model_validate(json.loads(args.attempt_selection.read_text(encoding="utf-8")))
    actual_plan_hash = _sha(args.plan)
    if args.plan_sha256 != actual_plan_hash:
        raise ValueError("--plan-sha256 does not match plan file bytes")
    records, per_record_hashes = _load_records(args.records, plans, selection)
    validate_formal_records(records, plans, selection, actual_plan_hash, record_hashes=per_record_hashes)
    selection_hash = _sha(args.attempt_selection)
    input_hashes = {"plan": actual_plan_hash, "records": _sha(args.records), "attempt_selection": selection_hash}
    if per_record_hashes:
        input_hashes.update({f"record:{run_id}": digest for run_id, digest in per_record_hashes.items()})
    print(json.dumps(write_analysis_bundle(records, args.output_dir, plan_hash=actual_plan_hash, attempt_selection_hash=selection_hash, input_record_hashes=input_hashes), sort_keys=True))
    return 0
if __name__ == "__main__": raise SystemExit(main())
