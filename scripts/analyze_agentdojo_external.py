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

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--attempt-selection", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args=parser.parse_args(argv)
    plans=[AgentDojoRunSpec.model_validate(row) for row in _rows(args.plan)]
    records=[AgentDojoResultRecord.model_validate(row) for row in _rows(args.records)]
    selection=AttemptSelectionManifest.model_validate(json.loads(args.attempt_selection.read_text(encoding="utf-8")))
    validate_formal_records(records, plans, selection, args.plan_sha256)
    selection_hash = _sha(args.attempt_selection)
    input_hashes = {"plan": _sha(args.plan), "records": _sha(args.records), "attempt_selection": selection_hash}
    print(json.dumps(write_analysis_bundle(records, args.output_dir, plan_hash=args.plan_sha256, attempt_selection_hash=selection_hash, input_record_hashes=input_hashes), sort_keys=True))
    return 0
if __name__ == "__main__": raise SystemExit(main())
