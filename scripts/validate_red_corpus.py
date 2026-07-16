#!/usr/bin/env python3
"""Verify every file and semantic registration in a frozen Red corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agentsec.redteam import verify_frozen_corpus  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument(
        "--allow-stub",
        action="store_true",
        help="permit formal_eligible=false deterministic fixture bundles",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = verify_frozen_corpus(
        args.corpus,
        require_formal_eligible=not args.allow_stub,
    )
    print(
        json.dumps(
            {
                "valid": True,
                "corpus": str(args.corpus.resolve()),
                "backend": manifest.generator_backend,
                "formal_eligible": manifest.formal_eligible,
                "model_id": manifest.model_id,
                "scenarios": len(manifest.scenarios),
                "candidate_artifacts": sum(
                    len(item.candidates) for item in manifest.scenarios
                ),
                "tracked_files": len(manifest.files),
                "manifest_sha256": (args.corpus / "manifest.sha256")
                .read_text(encoding="ascii")
                .strip(),
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
