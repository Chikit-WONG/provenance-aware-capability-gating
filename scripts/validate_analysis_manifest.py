#!/usr/bin/env python3
"""Validate hashes and scope of a publication analysis manifest.

The validator is intentionally read-only.  It verifies that the two legacy
output hash maps agree, that every declared output is a regular file beneath
the manifest directory, and that its bytes match the declared SHA-256 digest.
It does not inspect or delete raw/ignored run records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest(manifest_path: str | Path) -> dict[str, Any]:
    """Validate one analysis manifest and return a compact summary."""

    manifest = Path(manifest_path)
    if not manifest.is_file():
        raise FileNotFoundError(manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("analysis manifest must be a JSON object")
    outputs = payload.get("outputs")
    output_sha256 = payload.get("output_sha256")
    if not isinstance(outputs, dict) or not isinstance(output_sha256, dict):
        raise ValueError("manifest must contain object fields 'outputs' and 'output_sha256'")
    if outputs != output_sha256:
        raise ValueError("outputs and output_sha256 differ")

    root = manifest.parent.resolve()
    checked = 0
    for name, expected in sorted(outputs.items()):
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError(f"output path must be a basename: {name!r}")
        path = (root / name).resolve()
        if path.parent != root:
            raise ValueError(f"output escapes manifest directory: {name!r}")
        if not path.is_file():
            raise FileNotFoundError(path)
        if not isinstance(expected, str) or len(expected) != 64:
            raise ValueError(f"invalid SHA-256 digest for {name!r}")
        actual = _sha256(path)
        if actual != expected:
            raise ValueError(f"SHA-256 mismatch for {name}: expected {expected}, got {actual}")
        checked += 1
    return {"manifest": str(manifest), "checked_outputs": checked}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate_manifest(args.manifest), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
