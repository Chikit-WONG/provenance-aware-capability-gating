#!/usr/bin/env python3
"""Run the deterministic provenance sink pressure matrix."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentsec.pressure import run_sink_pressure_cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/sink-pressure-v1/results.json"),
    )
    args = parser.parse_args()
    rows = run_sink_pressure_cases()
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1",
        "case_count": len({row["case_id"] for row in rows}),
        "arm_count": len({row["defense_arm"] for row in rows}),
        "record_count": len(rows),
        "passed": all(row["passed"] for row in rows),
        "cases": rows,
    }
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
