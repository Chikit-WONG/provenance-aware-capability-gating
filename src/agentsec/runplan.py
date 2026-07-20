"""Deterministic construction and verification of the frozen formal run plan."""

from __future__ import annotations

import hashlib
import json
import random
from itertools import product
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .schemas import (
    ContentCondition,
    DefenseArm,
    RunSpec,
    ScenarioSpec,
    stable_model_hash,
)


FORMAL_SEEDS = (4313, 4314, 4315)
RANDOMIZATION_SEED = 4313
EXPECTED_FORMAL_RUNS = 216
FORMAL_DEFENSE_ARMS = (
    DefenseArm.ALLOW_ALL,
    DefenseArm.PROMPT_ONLY,
    DefenseArm.CAPABILITY_ONLY,
    DefenseArm.FULL,
)
ABLATION_DEFENSE_ARMS = (DefenseArm.PROMPT_CAPABILITY_ONLY,)


class FrozenRunPlanManifest(BaseModel):
    """Small, reproducible manifest stored beside ``run_plan.jsonl``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    plan_file: str = "run_plan.jsonl"
    plan_sha256: str
    record_count: int = Field(ge=1)
    randomization_seed: int
    formal_seeds: tuple[int, ...]
    model_config_hash: str
    corpus_manifest_sha256: str
    input_sha256: dict[str, str] = Field(default_factory=dict)
    plan_kind: Literal["formal", "provenance_ablation"] = "formal"
    defense_arms: tuple[DefenseArm, ...] = FORMAL_DEFENSE_ARMS

    @model_validator(mode="after")
    def defense_arms_match_plan_kind(self) -> "FrozenRunPlanManifest":
        expected_arms = (
            FORMAL_DEFENSE_ARMS
            if self.plan_kind == "formal"
            else ABLATION_DEFENSE_ARMS
        )
        if self.defense_arms != expected_arms:
            raise ValueError(
                f"{self.plan_kind} defense arms must be "
                f"{tuple(arm.value for arm in expected_arms)}"
            )
        return self


def build_formal_plan(
    scenarios: Sequence[ScenarioSpec],
    model_config: Mapping[str, Any] | BaseModel,
    *,
    formal_seeds: Sequence[int] = FORMAL_SEEDS,
    randomization_seed: int = RANDOMIZATION_SEED,
) -> tuple[RunSpec, ...]:
    """Build and once-shuffle the complete paired Cartesian design."""

    return _build_plan(
        scenarios,
        model_config,
        defense_arms=FORMAL_DEFENSE_ARMS,
        formal_seeds=formal_seeds,
        randomization_seed=randomization_seed,
    )


def build_ablation_plan(
    scenarios: Sequence[ScenarioSpec],
    model_config: Mapping[str, Any] | BaseModel,
    *,
    formal_seeds: Sequence[int] = FORMAL_SEEDS,
    randomization_seed: int = RANDOMIZATION_SEED,
) -> tuple[RunSpec, ...]:
    """Build the prompt-plus-capability provenance-ablation plan."""

    return _build_plan(
        scenarios,
        model_config,
        defense_arms=ABLATION_DEFENSE_ARMS,
        formal_seeds=formal_seeds,
        randomization_seed=randomization_seed,
    )


def _build_plan(
    scenarios: Sequence[ScenarioSpec],
    model_config: Mapping[str, Any] | BaseModel,
    *,
    defense_arms: Sequence[DefenseArm],
    formal_seeds: Sequence[int],
    randomization_seed: int,
) -> tuple[RunSpec, ...]:
    scenario_ids = tuple(item.scenario_id for item in scenarios)
    if len(scenario_ids) != 6 or len(set(scenario_ids)) != 6:
        raise ValueError("the formal plan requires six unique scenarios")
    seeds = tuple(int(seed) for seed in formal_seeds)
    if len(seeds) != 3 or len(set(seeds)) != 3:
        raise ValueError("the formal plan requires three unique paired seeds")
    arms = tuple(defense_arms)
    model_hash = stable_model_hash(model_config)
    records = [
        RunSpec(
            scenario_id=scenario_id,
            content_condition=condition,
            defense_arm=arm,
            seed=seed,
            repetition=repetition,
            model_config_hash=model_hash,
        )
        for scenario_id, condition, arm, (repetition, seed) in product(
            scenario_ids,
            tuple(ContentCondition),
            arms,
            tuple(enumerate(seeds)),
        )
    ]
    random.Random(randomization_seed).shuffle(records)
    validate_formal_plan(
        records,
        expected_scenario_ids=scenario_ids,
        expected_seeds=seeds,
        expected_model_config_hash=model_hash,
        expected_defense_arms=arms,
    )
    return tuple(records)


def freeze_formal_plan(
    output_dir: str | Path,
    records: Sequence[RunSpec],
    *,
    model_config_hash: str,
    corpus_manifest_sha256: str,
    input_sha256: Mapping[str, str] | None = None,
    formal_seeds: Sequence[int] = FORMAL_SEEDS,
    randomization_seed: int = RANDOMIZATION_SEED,
    plan_kind: Literal["formal", "provenance_ablation"] = "formal",
    defense_arms: Sequence[DefenseArm] = FORMAL_DEFENSE_ARMS,
) -> FrozenRunPlanManifest:
    """Write an immutable JSONL plan and its hash manifest.

    The target directory must not already exist.  This prevents an accidental
    re-randomization after any victim-model result has been observed.
    """

    encoded = _encode_plan(records)
    manifest = FrozenRunPlanManifest(
        plan_sha256=_sha256_bytes(encoded),
        record_count=len(records),
        randomization_seed=randomization_seed,
        formal_seeds=tuple(formal_seeds),
        model_config_hash=model_config_hash,
        corpus_manifest_sha256=corpus_manifest_sha256,
        input_sha256=dict(sorted((input_sha256 or {}).items())),
        plan_kind=plan_kind,
        defense_arms=tuple(defense_arms),
    )
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=False)
    plan_path = root / "run_plan.jsonl"
    with plan_path.open("xb") as handle:
        handle.write(encoded)
    with (root / "manifest.json").open("x", encoding="utf-8") as handle:
        json.dump(
            manifest.model_dump(mode="json"),
            handle,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        handle.write("\n")
    return manifest


def verify_frozen_plan(
    plan_dir: str | Path,
    *,
    expected_scenario_ids: Sequence[str] = ("T1", "T2", "T3", "T4", "T5", "T6"),
) -> tuple[FrozenRunPlanManifest, tuple[RunSpec, ...]]:
    """Hash-check and semantically validate a frozen run plan."""

    root = Path(plan_dir)
    manifest = FrozenRunPlanManifest.model_validate_json(
        (root / "manifest.json").read_text(encoding="utf-8")
    )
    plan_path = root / manifest.plan_file
    encoded = plan_path.read_bytes()
    actual_hash = _sha256_bytes(encoded)
    if actual_hash != manifest.plan_sha256:
        raise ValueError(
            f"run-plan SHA-256 mismatch: expected {manifest.plan_sha256}, got {actual_hash}"
        )
    records = load_run_plan(plan_path)
    if len(records) != manifest.record_count:
        raise ValueError("run-plan record count does not match manifest")
    validate_formal_plan(
        records,
        expected_scenario_ids=expected_scenario_ids,
        expected_seeds=manifest.formal_seeds,
        expected_model_config_hash=manifest.model_config_hash,
        expected_defense_arms=manifest.defense_arms,
    )
    return manifest, records


def load_run_plan(path: str | Path) -> tuple[RunSpec, ...]:
    records: list[RunSpec] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(RunSpec.model_validate_json(line))
            except Exception as exc:
                raise ValueError(f"invalid run-plan record at line {line_number}") from exc
    return tuple(records)


def validate_formal_plan(
    records: Iterable[RunSpec],
    *,
    expected_scenario_ids: Sequence[str],
    expected_seeds: Sequence[int] = FORMAL_SEEDS,
    expected_model_config_hash: str | None = None,
    expected_defense_arms: Sequence[DefenseArm] = FORMAL_DEFENSE_ARMS,
) -> None:
    """Reject missing, duplicate, added, or configuration-drifted cells."""

    rows = tuple(records)
    scenario_ids = tuple(expected_scenario_ids)
    seeds = tuple(expected_seeds)
    arms = tuple(expected_defense_arms)
    expected_cells = {
        (scenario_id, condition, arm, seed, repetition)
        for scenario_id, condition, arm, (repetition, seed) in product(
            scenario_ids,
            tuple(ContentCondition),
            arms,
            tuple(enumerate(seeds)),
        )
    }
    actual_cells = {
        (
            row.scenario_id,
            row.content_condition,
            row.defense_arm,
            row.seed,
            row.repetition,
        )
        for row in rows
    }
    if len(rows) != len(actual_cells):
        raise ValueError("run plan contains duplicate treatment cells")
    if actual_cells != expected_cells:
        missing = len(expected_cells - actual_cells)
        unexpected = len(actual_cells - expected_cells)
        raise ValueError(
            f"run plan is not the registered Cartesian design "
            f"(missing={missing}, unexpected={unexpected})"
        )
    run_ids = [row.run_id for row in rows]
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("run plan contains duplicate run IDs")
    if expected_model_config_hash is not None and any(
        row.model_config_hash != expected_model_config_hash for row in rows
    ):
        raise ValueError("run plan contains model configuration drift")
    expected_record_count = (
        len(scenario_ids) * len(tuple(ContentCondition)) * len(arms) * len(seeds)
    )
    if len(rows) != expected_record_count:
        raise ValueError(
            f"expected {expected_record_count} runs, found {len(rows)}"
        )


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _encode_plan(records: Sequence[RunSpec]) -> bytes:
    text = "".join(
        json.dumps(
            row.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for row in records
    )
    return text.encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


__all__ = [
    "ABLATION_DEFENSE_ARMS",
    "EXPECTED_FORMAL_RUNS",
    "FORMAL_DEFENSE_ARMS",
    "FORMAL_SEEDS",
    "FrozenRunPlanManifest",
    "RANDOMIZATION_SEED",
    "build_ablation_plan",
    "build_formal_plan",
    "freeze_formal_plan",
    "load_run_plan",
    "sha256_file",
    "validate_formal_plan",
    "verify_frozen_plan",
]
