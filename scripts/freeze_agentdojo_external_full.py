#!/usr/bin/env python3
"""Freeze all v1.2.2 AgentDojo suites for the canonical external check."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsec.agentdojo_external import (  # noqa: E402
    AGENTDOJO_SUITES,
    AgentDojoPair,
    AgentDojoRunSpec,
    build_matrix_plan,
    plan_jsonl,
)
from scripts.freeze_agentdojo_external import (  # noqa: E402
    EXPECTED_AGENTDOJO_COMMIT,
    EXPECTED_AGENTDOJO_TAG,
    EXPECTED_BENCHMARK_VERSION,
    EXPECTED_CHECKPOINT_PATH,
    EXPECTED_DEFENSES,
    EXPECTED_MODEL_DISPLAY_NAME,
    EXPECTED_SERVED_MODEL_NAME,
    ATTACK_NAMES,
    agentdojo_distribution_provenance,
    checkpoint_fingerprint,
    enumerate_official_pairs,
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _exclusive(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)


def _validate_config(config: Mapping[str, Any]) -> None:
    expected = {
        "agentdojo_commit": EXPECTED_AGENTDOJO_COMMIT,
        "agentdojo_tag": EXPECTED_AGENTDOJO_TAG,
        "benchmark_version": EXPECTED_BENCHMARK_VERSION,
        "attacks": list(ATTACK_NAMES),
        "defenses": list(EXPECTED_DEFENSES),
        "model_display_name": EXPECTED_MODEL_DISPLAY_NAME,
        "model_path": EXPECTED_CHECKPOINT_PATH,
        "served_model_name": EXPECTED_SERVED_MODEL_NAME,
        "suites": list(AGENTDOJO_SUITES),
        "temperature": 0.0,
        "tool_output_format": "json",
    }
    for key, value in expected.items():
        if config.get(key) != value:
            raise ValueError(f"full AgentDojo config drift in {key}: expected {value!r}")


def _write_json(path: Path, value: Any) -> str:
    payload = canonical_json(value) + b"\n"
    _exclusive(path, payload)
    return sha256_bytes(payload)


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> str:
    payload = b"".join(canonical_json(row) + b"\n" for row in rows)
    _exclusive(path, payload)
    return sha256_bytes(payload)


def freeze_full(
    config_path: str | Path,
    output_root: str | Path,
    *,
    enumerator: Callable[[str, str, str], tuple[list[AgentDojoPair], list[dict[str, Any]]]] = enumerate_official_pairs,
) -> dict[str, Any]:
    config_path = Path(config_path)
    output_root = Path(output_root)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    _validate_config(config)
    checkpoint_hash = checkpoint_fingerprint(config["model_path"])
    if output_root.exists():
        raise FileExistsError(f"full freeze destination already exists: {output_root}")
    output_root.mkdir(parents=True)
    summaries: list[dict[str, Any]] = []
    for suite_name in AGENTDOJO_SUITES:
        candidates, screening = enumerator(config["benchmark_version"], suite_name, config["served_model_name"])
        pairs = sorted((pair for pair in candidates if pair.runnable), key=lambda pair: (pair.canonical_sha256, pair.canonical_key))
        if len(pairs) < 2:
            raise ValueError(f"suite {suite_name} has fewer than two runnable pairs")
        if any(pair.suite != suite_name for pair in pairs):
            raise ValueError(f"suite {suite_name} enumerator returned a mismatched pair")
        all_users = sorted({str(row["user_task_id"]) for row in screening})
        development_pairs = pairs[:2]
        formal_pairs = pairs[2:]
        development_users = tuple(all_users[:2])
        formal_users = tuple(user for user in all_users if user not in set(development_users))
        model_hash = sha256_bytes(canonical_json({"model": config["served_model_name"], "temperature": config["temperature"], "tool_output_format": config["tool_output_format"]}))
        development = build_matrix_plan(development_pairs, model_hash, phase="development", suite_name=suite_name, clean_user_task_ids=development_users)
        formal = build_matrix_plan(formal_pairs, model_hash, phase="formal", suite_name=suite_name, clean_user_task_ids=formal_users)
        suite_dir = output_root / suite_name
        suite_dir.mkdir()
        screening_hash = _write_jsonl(suite_dir / "screening.jsonl", screening)
        selected_rows = [pair.model_dump(mode="json") for pair in pairs]
        selected_hash = _write_jsonl(suite_dir / "selected_pairs.jsonl", selected_rows)
        dev_bytes = plan_jsonl(development).encode()
        formal_bytes = plan_jsonl(formal).encode()
        _exclusive(suite_dir / "development_plan.jsonl", dev_bytes)
        _exclusive(suite_dir / "formal_plan.jsonl", formal_bytes)
        env_payload = ("agentdojo_commit=" + EXPECTED_AGENTDOJO_COMMIT + "\n" + "agentdojo_tag=" + EXPECTED_AGENTDOJO_TAG + "\n" + "benchmark_version=" + EXPECTED_BENCHMARK_VERSION + "\n" + "suite=" + suite_name + "\n" + "model_config_hash=" + model_hash + "\n" + "model_checkpoint_sha256=" + checkpoint_hash + "\n").encode()
        _exclusive(suite_dir / "environment.txt", env_payload)
        suite_manifest = {
            "schema_version": "full-1",
            "suite": suite_name,
            "agentdojo_commit": EXPECTED_AGENTDOJO_COMMIT,
            "agentdojo_tag": EXPECTED_AGENTDOJO_TAG,
            "benchmark_version": EXPECTED_BENCHMARK_VERSION,
            "model_config_hash": model_hash,
            "model_checkpoint_sha256": checkpoint_hash,
            "screened_pair_count": len(candidates),
            "selected_pair_count": len(pairs),
            "development_pair_count": len(development_pairs),
            "formal_pair_count": len(formal_pairs),
            "development_attacked_count": sum(row.attack != "none" for row in development),
            "development_clean_count": sum(row.attack == "none" for row in development),
            "formal_attacked_count": sum(row.attack != "none" for row in formal),
            "formal_clean_count": sum(row.attack == "none" for row in formal),
            "formal_total_count": len(formal),
            "screening_sha256": screening_hash,
            "selected_pairs_sha256": selected_hash,
            "development_plan_sha256": sha256_bytes(dev_bytes),
            "formal_plan_sha256": sha256_bytes(formal_bytes),
        }
        manifest_hash = _write_json(suite_dir / "manifest.json", suite_manifest)
        summaries.append(suite_manifest | {"manifest_sha256": manifest_hash})
    top = {
        "schema_version": "full-1",
        "agentdojo_commit": EXPECTED_AGENTDOJO_COMMIT,
        "agentdojo_tag": EXPECTED_AGENTDOJO_TAG,
        "benchmark_version": EXPECTED_BENCHMARK_VERSION,
        "suites": list(AGENTDOJO_SUITES),
        "attacks": list(ATTACK_NAMES),
        "defenses": list(EXPECTED_DEFENSES),
        "model_path": config["model_path"],
        "model_checkpoint_sha256": checkpoint_hash,
        "config_sha256": sha256_bytes(config_path.read_bytes()),
        "suite_manifests": summaries,
        "development_total_count": sum(row["development_attacked_count"] + row["development_clean_count"] for row in summaries),
        "formal_attacked_count": sum(row["formal_attacked_count"] for row in summaries),
        "formal_clean_count": sum(row["formal_clean_count"] for row in summaries),
        "formal_total_count": sum(row["formal_total_count"] for row in summaries),
    }
    _write_json(output_root / "plan_manifest.json", top)
    return top


def verify_full(output_root: str | Path, config_path: str | Path) -> dict[str, Any]:
    root = Path(output_root)
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    _validate_config(config)
    top = json.loads((root / "plan_manifest.json").read_text(encoding="utf-8"))
    if top["suites"] != list(AGENTDOJO_SUITES):
        raise ValueError("top-level suite list drifted")
    total = 0
    for suite_name in AGENTDOJO_SUITES:
        suite_dir = root / suite_name
        manifest = json.loads((suite_dir / "manifest.json").read_text(encoding="utf-8"))
        plan = [AgentDojoRunSpec.model_validate(json.loads(line)) for line in (suite_dir / "formal_plan.jsonl").read_text().splitlines() if line]
        if any(row.suite != suite_name or row.phase != "formal" for row in plan):
            raise ValueError(f"formal plan identity drift for {suite_name}")
        digest = sha256_bytes((suite_dir / "formal_plan.jsonl").read_bytes())
        if digest != manifest["formal_plan_sha256"]:
            raise ValueError(f"formal plan hash mismatch for {suite_name}")
        total += len(plan)
    if total != top["formal_total_count"]:
        raise ValueError("top-level formal count mismatch")
    return {"verified": True, "suite_count": len(AGENTDOJO_SUITES), "formal_total_count": total}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args(argv)
    if bool(args.output) == bool(args.verify):
        parser.error("choose exactly one of --output or --verify")
    result = freeze_full(args.config, args.output) if args.output else verify_full(args.verify, args.config)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
