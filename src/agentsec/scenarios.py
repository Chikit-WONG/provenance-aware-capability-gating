"""Loading and validation helpers for the six pre-registered scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .schemas import ContentCondition, ScenarioSpec


EXPECTED_SCENARIO_IDS = ("T1", "T2", "T3", "T4", "T5", "T6")
DEFAULT_SCENARIO_DIR = Path(__file__).resolve().parents[2] / "configs" / "scenarios"


def load_scenario(path_or_id: str | Path, *, directory: str | Path | None = None) -> ScenarioSpec:
    """Load one scenario by JSON path or stable ID."""

    path = Path(path_or_id)
    if not path.exists():
        root = Path(directory) if directory is not None else DEFAULT_SCENARIO_DIR
        path = root / f"{path_or_id}.json"
    with path.open("r", encoding="utf-8") as handle:
        spec = ScenarioSpec.model_validate(json.load(handle))
    validate_scenario(spec)
    return spec


def load_scenarios(directory: str | Path | None = None) -> tuple[ScenarioSpec, ...]:
    """Load the complete ordered T1--T6 suite and reject omissions/extras."""

    root = Path(directory) if directory is not None else DEFAULT_SCENARIO_DIR
    paths = sorted(root.glob("*.json"))
    scenarios = tuple(load_scenario(path) for path in paths)
    ids = tuple(scenario.scenario_id for scenario in scenarios)
    if len(set(ids)) != len(ids):
        raise ValueError(f"duplicate scenario IDs in {root}")
    missing = set(EXPECTED_SCENARIO_IDS) - set(ids)
    unexpected = set(ids) - set(EXPECTED_SCENARIO_IDS)
    if missing or unexpected:
        raise ValueError(
            f"scenario suite mismatch: missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)}"
        )
    by_id = {scenario.scenario_id: scenario for scenario in scenarios}
    return tuple(by_id[scenario_id] for scenario_id in EXPECTED_SCENARIO_IDS)


def validate_scenario(spec: ScenarioSpec) -> None:
    """Check experiment invariants not expressible by the shared schema."""

    payload_keys = {
        getattr(key, "value", key) for key in spec.condition_payloads.keys()
    }
    expected_conditions = {condition.value for condition in ContentCondition}
    if payload_keys != expected_conditions:
        raise ValueError(
            f"scenario {spec.scenario_id}: expected payloads {expected_conditions}, "
            f"got {payload_keys}"
        )

    dumped = spec.initial_world.model_dump_json()
    if dumped.count("{{CONDITION_PAYLOAD}}") != 1:
        raise ValueError(
            f"scenario {spec.scenario_id}: exactly one condition placeholder is required"
        )

    for protected in spec.protected_values:
        if protected.value not in dumped:
            raise ValueError(
                f"scenario {spec.scenario_id}: protected value "
                f"{protected.protected_id!r} is absent from the initial world"
            )

    capability_ids = [capability.capability_id for capability in spec.capabilities]
    if len(capability_ids) != len(set(capability_ids)):
        raise ValueError(f"scenario {spec.scenario_id}: duplicate capability ID")


def scenario_ids(scenarios: Iterable[ScenarioSpec]) -> tuple[str, ...]:
    return tuple(scenario.scenario_id for scenario in scenarios)
