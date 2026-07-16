"""Materialize clean, placebo, or attack content without mutating a scenario."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .schemas import ContentCondition, ScenarioSpec, WorldState


CONDITION_PLACEHOLDER = "{{CONDITION_PAYLOAD}}"


def materialize_condition(
    scenario: ScenarioSpec,
    condition: ContentCondition | str,
    *,
    payload_base_dir: str | Path | None = None,
) -> WorldState:
    """Return a fresh world with the selected condition payload inserted.

    A scenario must contain exactly one placeholder.  Enforcing this prevents a
    typo from producing a benchmark run in which the attack was never exposed.
    ``payload_base_dir`` is reserved for frozen ``file:`` references; relative
    references are resolved beneath it and cannot escape that directory.
    """

    selected = _coerce_condition(condition)
    payloads: Mapping[Any, Any] = scenario.condition_payloads
    raw_payload = _lookup_payload(payloads, selected)
    payload = resolve_payload(raw_payload, base_dir=payload_base_dir)

    world_data = scenario.initial_world.model_dump(mode="python")
    placeholder_count = 0
    for email in world_data.get("emails", {}).values():
        body = email.get("body", "")
        count = body.count(CONDITION_PLACEHOLDER)
        if count:
            email["body"] = body.replace(CONDITION_PLACEHOLDER, payload)
            placeholder_count += count

    if placeholder_count != 1:
        raise ValueError(
            f"scenario {scenario.scenario_id!r} must contain exactly one "
            f"{CONDITION_PLACEHOLDER!r}; found {placeholder_count}"
        )
    return WorldState.model_validate(world_data)


def resolve_payload(payload: str, *, base_dir: str | Path | None = None) -> str:
    """Resolve an inline payload or an explicitly based ``file:`` reference."""

    if not isinstance(payload, str):
        raise TypeError("condition payload must be a string")
    if not payload.startswith("file:"):
        return payload
    if base_dir is None:
        raise ValueError("payload_base_dir is required for file: payload references")

    root = Path(base_dir).resolve()
    candidate = (root / payload.removeprefix("file:")).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("payload file reference escapes payload_base_dir") from exc
    return candidate.read_text(encoding="utf-8")


def _lookup_payload(payloads: Mapping[Any, Any], condition: ContentCondition) -> str:
    for key in (condition, condition.value):
        try:
            return payloads[key]
        except KeyError:
            pass
    raise KeyError(f"scenario has no payload for condition {condition.value!r}")


def _coerce_condition(value: ContentCondition | str) -> ContentCondition:
    if isinstance(value, ContentCondition):
        return value
    if isinstance(value, Enum):
        value = value.value
    return ContentCondition(value)
