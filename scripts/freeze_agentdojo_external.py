#!/usr/bin/env python3
"""Freeze an outcome-independent native AgentDojo Workspace slice.

The default path imports AgentDojo lazily and only calls its official attack
constructors.  It never creates a victim pipeline and never contacts vLLM.
The resulting directory is append-free: a second freeze refuses to overwrite
an existing destination.  ``--verify`` checks the persisted hashes and plan
semantics without importing AgentDojo at all.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentsec.agentdojo_external import (  # noqa: E402
    AgentDojoFrozenManifest,
    AgentDojoPair,
    AgentDojoRunSpec,
    build_development_plan,
    build_formal_plan,
    canonical_pair,
    plan_jsonl,
    select_agentdojo_pairs,
    validate_agentdojo_plan,
)
from agentsec.schemas import stable_model_hash  # noqa: E402


ATTACK_NAMES = ("important_instructions", "tool_knowledge")
EXPECTED_AGENTDOJO_VERSION = "0.1.35"
EXPECTED_AGENTDOJO_COMMIT = "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
EXPECTED_AGENTDOJO_TAG = "v0.1.35"
EXPECTED_BENCHMARK_VERSION = "v1.2.2"
EXPECTED_SUITE = "workspace"
EXPECTED_SERVED_MODEL_NAME = "qwen3-vl-8b"
EXPECTED_MODEL_DISPLAY_NAME = "Qwen"
EXPECTED_CHECKPOINT_PATH = "/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct"
EXPECTED_DEFENSES = ("none", "repeat_user_prompt")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
    )


def checkpoint_fingerprint(path: str | Path) -> str:
    """Hash a checkpoint directory deterministically, independent of mtimes.

    Each regular file contributes its POSIX relative path, byte length, and
    content digest.  Symlinks are represented by their target text, so a
    symlink cannot silently alias a changing file outside the checkpoint.
    """

    root = Path(path)
    if not root.is_absolute():
        raise ValueError("model checkpoint path must be absolute")
    if not root.is_dir():
        raise FileNotFoundError(f"model checkpoint directory not found: {root}")
    entries: list[tuple[str, str, int, str]] = []
    for item in sorted(root.rglob("*"), key=lambda candidate: candidate.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        if item.is_symlink():
            target = item.readlink().as_posix()
            entries.append(("symlink", relative, len(target.encode()), sha256_bytes(target.encode())))
        elif item.is_file():
            size = item.stat().st_size
            entries.append(("file", relative, size, sha256_file(item)))
    digest = hashlib.sha256()
    digest.update(b"agentdojo-checkpoint-fingerprint-v1\n")
    for kind, relative, size, content_hash in entries:
        digest.update(kind.encode("ascii"))
        digest.update(b"\0")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(content_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _agentdojo_version() -> str:
    try:
        version = importlib.metadata.version("agentdojo")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError("AgentDojo is not installed in this environment") from exc
    if version != EXPECTED_AGENTDOJO_VERSION:
        raise RuntimeError(
            f"AgentDojo version must be {EXPECTED_AGENTDOJO_VERSION}, found {version}"
        )
    return version


def agentdojo_distribution_provenance() -> dict[str, str]:
    """Require immutable VCS evidence for the installed AgentDojo package."""

    distribution = importlib.metadata.distribution("agentdojo")
    raw_direct_url = distribution.read_text("direct_url.json")
    if not raw_direct_url:
        raise RuntimeError("AgentDojo direct_url.json is missing; immutable commit evidence is required")
    try:
        direct_url = json.loads(raw_direct_url)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AgentDojo direct_url.json is malformed") from exc
    vcs_info = direct_url.get("vcs_info") or {}
    commit = vcs_info.get("commit_id")
    if vcs_info.get("vcs") != "git" or commit != EXPECTED_AGENTDOJO_COMMIT:
        raise RuntimeError(f"AgentDojo direct_url commit must be {EXPECTED_AGENTDOJO_COMMIT}, found {commit!r}")
    return {
        "direct_url": str(direct_url.get("url", "")),
        "vcs": str(vcs_info.get("vcs", "")),
        "commit_id": str(commit),
    }

def _validate_config(config: Mapping[str, Any]) -> None:
    """Reject any drift from the approved native AgentDojo experiment."""

    expected: dict[str, Any] = {
        "agentdojo_commit": EXPECTED_AGENTDOJO_COMMIT,
        "agentdojo_tag": EXPECTED_AGENTDOJO_TAG,
        "benchmark_version": EXPECTED_BENCHMARK_VERSION,
        "suite": EXPECTED_SUITE,
        "attacks": list(ATTACK_NAMES),
        "defenses": list(EXPECTED_DEFENSES),
        "model_display_name": EXPECTED_MODEL_DISPLAY_NAME,
        "model_path": EXPECTED_CHECKPOINT_PATH,
        "served_model_name": EXPECTED_SERVED_MODEL_NAME,
        "temperature": 0.0,
        "tool_output_format": "json",
    }
    for key, expected_value in expected.items():
        if config.get(key) != expected_value:
            raise ValueError(f"external AgentDojo config drift in {key}: expected {expected_value!r}")


def build_official_attacks(benchmark_version: str, suite_name: str, model_name: str) -> tuple[Any, dict[str, Any]]:
    """Load the official suite and attacks without constructing a victim LLM."""

    # These imports are intentionally inside the function.  The controller
    # environment and verification tests do not need AgentDojo installed.
    from agentdojo.agent_pipeline import AgentPipeline
    from agentdojo.attacks import load_attack
    from agentdojo.models import MODEL_NAMES
    from agentdojo.task_suite import get_suite

    suite = get_suite(benchmark_version, suite_name)
    selection_pipeline = AgentPipeline([])
    selection_pipeline.name = model_name
    MODEL_NAMES[model_name] = "Qwen"
    attacks = {
        name: load_attack(name, suite, selection_pipeline)
        for name in ATTACK_NAMES
    }
    return suite, attacks


def _attack_digest(value: Any) -> str:
    try:
        return sha256_bytes(canonical_json(value))
    except (TypeError, ValueError):
        return sha256_bytes(repr(value).encode("utf-8"))


def enumerate_official_pairs(
    benchmark_version: str,
    suite_name: str,
    model_name: str,
) -> tuple[list[AgentDojoPair], list[dict[str, Any]]]:
    """Screen every suite pair with both official attacks before inference."""

    suite, attacks = build_official_attacks(benchmark_version, suite_name, model_name)
    candidates: list[AgentDojoPair] = []
    screening: list[dict[str, Any]] = []
    for user_task_id in sorted(suite.user_tasks):
        user_task = suite.user_tasks[user_task_id]
        for injection_task_id in sorted(suite.injection_tasks):
            injection_task = suite.injection_tasks[injection_task_id]
            outcomes: dict[str, dict[str, Any]] = {}
            reasons: list[str] = []
            for attack_name, attack in attacks.items():
                try:
                    result = attack.attack(user_task, injection_task)
                    nonempty = isinstance(result, Mapping) and bool(result)
                    outcomes[attack_name] = {
                        "nonempty": nonempty,
                        "result_sha256": _attack_digest(result),
                    }
                    if not nonempty:
                        reasons.append(f"{attack_name}: empty injection dictionary")
                except Exception as exc:  # noqa: BLE001 - reason is frozen evidence
                    message = str(exc).replace("\n", " ")
                    outcomes[attack_name] = {
                        "nonempty": False,
                        "exception_class": type(exc).__name__,
                        "exception_message": message,
                    }
                    reasons.append(f"{attack_name}: {type(exc).__name__}: {message}")
            runnable = not reasons
            pair = canonical_pair(user_task_id, injection_task_id)
            if not runnable:
                pair = AgentDojoPair(
                    **pair.model_dump(), runnable=False, exclusion_reason="; ".join(reasons)
                )
            candidates.append(pair)
            screening.append(
                {
                    "canonical_key": pair.canonical_key,
                    "canonical_sha256": pair.canonical_sha256,
                    "user_task_id": user_task_id,
                    "injection_task_id": injection_task_id,
                    "runnable": runnable,
                    "exclusion_reason": pair.exclusion_reason,
                    "attacks": outcomes,
                }
            )
    screening.sort(key=lambda row: (row["canonical_sha256"], row["canonical_key"]))
    return candidates, screening


def _jsonl_bytes(rows: list[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json(row) + b"\n" for row in rows)


def _exclusive_write(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)


def _environment_text(
    *,
    config: Mapping[str, Any],
    package_version: str,
    source_sha256: str,
    config_sha256: str,
    requirements_sha256: str,
    provenance: Mapping[str, str],
) -> str:
    try:
        freeze = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except OSError as exc:
        freeze = f"pip_freeze_error={type(exc).__name__}: {exc}"
    lines = [
        f"python={sys.version.split()[0]}",
        f"platform={platform.platform()}",
        f"agentdojo_version={package_version}",
        f"agentdojo_commit={config['agentdojo_commit']}",
        f"agentdojo_tag={config['agentdojo_tag']}",
        f"benchmark_version={config['benchmark_version']}",
        f"suite={config['suite']}",
        "model_name_registration=qwen3-vl-8b -> Qwen",
        f"source_sha256={source_sha256}",
        f"config_sha256={config_sha256}",
        f"agentdojo_direct_url={provenance.get('direct_url', '')}",
        f"agentdojo_vcs={provenance.get('vcs', '')}",
        f"agentdojo_installed_commit={provenance.get('commit_id', '')}",
        f"requirements_sha256={requirements_sha256}",
        "pip_freeze_begin",
        freeze,
        "pip_freeze_end",
    ]
    return "\n".join(lines) + "\n"


def freeze_slice(
    config_path: Path,
    output_dir: Path,
    *,
    enumerator: Callable[[str, str, str], tuple[list[AgentDojoPair], list[dict[str, Any]]]] = enumerate_official_pairs,
) -> dict[str, Any]:
    config_path = config_path.resolve()
    output_dir = output_dir.resolve()
    project_root = PROJECT_ROOT.resolve()
    if output_dir.exists():
        raise FileExistsError(f"freeze output already exists: {output_dir}")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    _validate_config(config)
    required = ("agentdojo_commit", "agentdojo_tag", "benchmark_version", "suite", "served_model_name", "model_path")
    missing = [name for name in required if name not in config]
    if missing:
        raise ValueError(f"external AgentDojo config missing fields: {missing}")
    model_path = Path(config["model_path"])
    if not model_path.is_absolute():
        raise ValueError("model_path must be absolute")
    model_path = model_path.resolve()
    if not model_path.is_dir():
        raise FileNotFoundError(f"model checkpoint directory not found: {model_path}")
    requirements_path = project_root / "requirements-agentdojo-external.txt"
    if not requirements_path.is_file():
        raise FileNotFoundError(requirements_path)
    try:
        package_version = _agentdojo_version()
        provenance = agentdojo_distribution_provenance()
    except (RuntimeError, importlib.metadata.PackageNotFoundError):
        if enumerator is enumerate_official_pairs:
            raise
        package_version = "unavailable-in-mocked-enumerator"
        provenance = {"direct_url": "", "vcs": "", "commit_id": ""}
    config_sha256 = sha256_file(config_path)
    source_sha256 = sha256_file(requirements_path)
    checkpoint_sha256 = checkpoint_fingerprint(model_path)
    model_config_hash = stable_model_hash(config)
    candidates, screening = enumerator(
        config["benchmark_version"], config["suite"], config["served_model_name"]
    )
    selected = select_agentdojo_pairs(candidates)
    development = selected[:2]
    formal = selected[2:]
    development_plan = build_development_plan(development, model_config_hash)
    formal_plan = build_formal_plan(formal, model_config_hash)
    selected_rows = [pair.model_dump(mode="json") for pair in selected]
    development_bytes = plan_jsonl(development_plan).encode("utf-8")
    formal_bytes = plan_jsonl(formal_plan).encode("utf-8")
    selected_bytes = _jsonl_bytes(selected_rows)
    screening_bytes = _jsonl_bytes(screening)
    environment_text = _environment_text(
        config=config,
        package_version=package_version,
        source_sha256=source_sha256,
        provenance=provenance,
        config_sha256=config_sha256,
        requirements_sha256=source_sha256,
    ).encode("utf-8")
    output_dir.mkdir(parents=True, exist_ok=False)
    _exclusive_write(output_dir / "screening.jsonl", screening_bytes)
    _exclusive_write(output_dir / "selected_pairs.jsonl", selected_bytes)
    _exclusive_write(output_dir / "development_plan.jsonl", development_bytes)
    _exclusive_write(output_dir / "formal_plan.jsonl", formal_bytes)
    _exclusive_write(output_dir / "environment.txt", environment_text)
    formal_attacked_count = sum(row.attack != "none" for row in formal_plan)
    formal_clean_count = sum(row.attack == "none" for row in formal_plan)
    manifest = AgentDojoFrozenManifest(
        agentdojo_commit=config["agentdojo_commit"],
        agentdojo_tag=config["agentdojo_tag"],
        benchmark_version=config["benchmark_version"],
        suite=config["suite"],
        source_sha256=source_sha256,
        agentdojo_source_commit=provenance.get("commit_id", ""),
        config_sha256=config_sha256,
        model_config_hash=model_config_hash,
        served_model_name=config["served_model_name"],
        model_checkpoint_path=str(model_path),
        model_checkpoint_sha256=checkpoint_sha256,
        selected_pair_ids=tuple(pair.canonical_key for pair in selected),
        development_pair_ids=tuple(pair.canonical_key for pair in development),
        formal_pair_ids=tuple(pair.canonical_key for pair in formal),
        development_plan_sha256=sha256_bytes(development_bytes),
        formal_plan_sha256=sha256_bytes(formal_bytes),
        selected_pair_count=len(selected),
        development_pair_count=len(development),
        formal_pair_count=len(formal),
        formal_attacked_count=formal_attacked_count,
        formal_clean_count=formal_clean_count,
        formal_total_count=len(formal_plan),
        screening_sha256=sha256_bytes(screening_bytes),
        selected_pairs_sha256=sha256_bytes(selected_bytes),
        environment_sha256=sha256_bytes(environment_text),
    )
    _exclusive_write(
        output_dir / "manifest.json",
        canonical_json(manifest.model_dump(mode="json")) + b"\n",
    )
    return {
        "selected_pair_count": len(selected),
        "development_pair_count": len(development),
        "formal_pair_count": len(formal),
        "formal_attacked_count": formal_attacked_count,
        "formal_clean_count": formal_clean_count,
        "formal_total_count": len(formal_plan),
        "screened_pair_count": len(screening),
        "output_dir": str(output_dir),
    }


def verify_slice(output_dir: Path, config_path: Path) -> dict[str, Any]:
    """Verify artifacts against an independently supplied runtime config."""
    output_dir = output_dir.resolve()
    config_path = config_path.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    _validate_config(config)
    runtime_model_path = Path(config["model_path"])
    if not runtime_model_path.is_absolute():
        raise ValueError("model_path must be absolute")
    runtime_model_path = runtime_model_path.resolve()
    runtime_checkpoint_sha256 = checkpoint_fingerprint(runtime_model_path)
    runtime_model_config_hash = stable_model_hash(config)
    manifest_path = output_dir / "manifest.json"
    manifest = AgentDojoFrozenManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    if manifest.config_sha256 != sha256_file(config_path):
        raise ValueError("manifest config_sha256 does not match runtime config")
    requirements_path = PROJECT_ROOT / "requirements-agentdojo-external.txt"
    if manifest.source_sha256 != sha256_file(requirements_path):
        raise ValueError("manifest source_sha256 does not match pinned requirements")
    if manifest.agentdojo_source_commit and manifest.agentdojo_source_commit != EXPECTED_AGENTDOJO_COMMIT:
        raise ValueError("manifest AgentDojo source commit is not the approved immutable revision")
    files = {
        "screening_sha256": output_dir / "screening.jsonl",
        "selected_pairs_sha256": output_dir / "selected_pairs.jsonl",
        "development_plan_sha256": output_dir / "development_plan.jsonl",
        "formal_plan_sha256": output_dir / "formal_plan.jsonl",
        "environment_sha256": output_dir / "environment.txt",
    }
    for field, path in files.items():
        actual = sha256_file(path)
        expected = getattr(manifest, field)
        if not expected or actual != expected:
            raise ValueError(f"{path.name} hash mismatch")
    selected = [AgentDojoPair.model_validate(json.loads(line)) for line in (output_dir / "selected_pairs.jsonl").read_text(encoding="utf-8").splitlines() if line]
    selected_keys = tuple(pair.canonical_key for pair in selected)
    if selected_keys != manifest.selected_pair_ids:
        raise ValueError("selected_pairs.jsonl does not match manifest selected_pair_ids")
    if len(selected) != manifest.selected_pair_count or len(selected[:2]) != manifest.development_pair_count or len(selected[2:]) != manifest.formal_pair_count:
        raise ValueError("manifest pair counts do not match selected_pairs.jsonl")
    screening_rows = [json.loads(line) for line in (output_dir / "screening.jsonl").read_text(encoding="utf-8").splitlines() if line]
    screening_by_key = {row.get("canonical_key"): row for row in screening_rows}
    if len(screening_by_key) != len(screening_rows):
        raise ValueError("screening.jsonl contains duplicate canonical keys")
    for pair in selected:
        screen = screening_by_key.get(pair.canonical_key)
        if screen is None or not screen.get("runnable", False):
            raise ValueError("selected pair is missing from runnable screening records")
    development = selected[:2]
    formal = selected[2:]
    development_rows = [AgentDojoRunSpec.model_validate(json.loads(line)) for line in (output_dir / "development_plan.jsonl").read_text(encoding="utf-8").splitlines() if line]
    formal_rows = [AgentDojoRunSpec.model_validate(json.loads(line)) for line in (output_dir / "formal_plan.jsonl").read_text(encoding="utf-8").splitlines() if line]
    expected_development_count = manifest.development_pair_count * 4 + 2 * len({pair.user_task_id for pair in development})
    if len(development_rows) != expected_development_count:
        raise ValueError("development plan count does not match manifest")
    if len(formal_rows) != manifest.formal_total_count:
        raise ValueError("formal plan count does not match manifest")
    formal_attacked = sum(row.attack != "none" for row in formal_rows)
    formal_clean = sum(row.attack == "none" for row in formal_rows)
    if (formal_attacked, formal_clean, len(formal_rows)) != (manifest.formal_attacked_count, manifest.formal_clean_count, manifest.formal_total_count):
        raise ValueError("manifest formal cell counts do not match formal_plan.jsonl")
    runtime_identity = {
        "served_model_name": config["served_model_name"],
        "model_checkpoint_path": str(runtime_model_path),
        "model_checkpoint_sha256": runtime_checkpoint_sha256,
    }
    validate_agentdojo_plan(development_rows, development, runtime_model_config_hash, phase="development", manifest=manifest, **runtime_identity)
    validate_agentdojo_plan(formal_rows, formal, runtime_model_config_hash, phase="formal", manifest=manifest, **runtime_identity)
    return {"verified": True, "output_dir": str(output_dir), "formal_total_count": manifest.formal_total_count}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, help="external config for freeze or independent verification")
    parser.add_argument("--verify", type=Path, metavar="OUTPUT_DIR")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if (args.config is None) == (args.verify is None):
        parser.error("provide --config for freeze, or --verify OUTPUT_DIR together with --config")
    if args.verify is not None:
        print(json.dumps(verify_slice(args.verify, args.config), sort_keys=True))
        return 0
    if args.output_dir is None:
        parser.error("--output-dir is required when freezing")
    summary = freeze_slice(args.config, args.output_dir)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
