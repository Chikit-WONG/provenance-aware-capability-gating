"""Read-only loading and presentation helpers for experiment attempts.

The replay path deliberately depends only on the Python standard library.  A
demo can therefore inspect saved evidence even when the model server, Gradio,
or the live orchestration stack is unavailable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class ArtifactFormatError(ValueError):
    """A selected directory is not a self-consistent attempt artifact."""


@dataclass(frozen=True)
class ReplayArtifact:
    """The immutable evidence needed by the demo's replay view."""

    directory: Path | None
    run_spec: dict[str, Any]
    result: dict[str, Any]
    audit_events: tuple[dict[str, Any], ...]
    world_before: dict[str, Any]
    world_after: dict[str, Any]
    final_response: str
    reader_trace: dict[str, Any] | None = None
    action_trace: dict[str, Any] | None = None

    @property
    def run_id(self) -> str:
        return str(self.run_spec.get("run_id") or self.result.get("run_id") or "unknown")

    @property
    def scenario_id(self) -> str:
        return str(self.run_spec.get("scenario_id", "unknown"))


def discover_attempts(root: str | Path, *, limit: int = 500) -> list[Path]:
    """Return valid-looking attempt directories in deterministic path order."""

    path = Path(root).expanduser()
    if limit < 1:
        raise ValueError("limit must be positive")
    if not path.exists():
        return []
    if path.is_file():
        path = path.parent
    if _is_attempt_dir(path):
        return [path.resolve()]

    attempts: list[Path] = []
    for result_file in sorted(path.rglob("result.json")):
        candidate = result_file.parent
        if _is_attempt_dir(candidate):
            attempts.append(candidate.resolve())
            if len(attempts) >= limit:
                break
    return attempts


def load_replay_artifact(path: str | Path) -> ReplayArtifact:
    """Load one persisted attempt, rejecting ambiguous artifact roots."""

    selected = Path(path).expanduser()
    if selected.is_file():
        selected = selected.parent
    if not selected.exists():
        raise ArtifactFormatError(f"artifact path does not exist: {selected}")
    if not _is_attempt_dir(selected):
        candidates = discover_attempts(selected)
        if not candidates:
            raise ArtifactFormatError(f"no attempt artifacts found under: {selected}")
        if len(candidates) > 1:
            raise ArtifactFormatError(
                f"artifact root contains {len(candidates)} attempts; select one attempt directory"
            )
        selected = candidates[0]

    run_spec = _read_object(selected / "run_spec.json", required=True)
    result = _read_object(selected / "result.json", required=True)
    world_before = _read_object(selected / "world_before.json", required=False)
    world_after = _read_object(selected / "world_after.json", required=False)
    final_payload = _read_object(selected / "final_response.json", required=False)
    final_response = str(final_payload.get("final_response", ""))
    events = _read_jsonl(selected / "audit.jsonl")
    reader_trace = _read_optional_object(selected / "reader_trace.json")
    action_trace = _read_optional_object(selected / "action_trace.json")

    artifact = ReplayArtifact(
        directory=selected.resolve(),
        run_spec=run_spec,
        result=result,
        audit_events=events,
        world_before=world_before,
        world_after=world_after,
        final_response=final_response,
        reader_trace=reader_trace,
        action_trace=action_trace,
    )
    _validate_artifact(artifact)
    return artifact


def artifact_from_mapping(value: Mapping[str, Any]) -> ReplayArtifact:
    """Normalize an in-memory result returned by a live-run adapter."""

    for directory_field in ("artifact_dir", "artifact_directory", "attempt_dir"):
        if value.get(directory_field):
            return load_replay_artifact(value[directory_field])

    events_value = value.get("audit_events", value.get("audit", ()))
    if not isinstance(events_value, Sequence) or isinstance(events_value, (str, bytes)):
        raise ArtifactFormatError("audit_events must be a sequence of JSON objects")
    events: list[dict[str, Any]] = []
    for index, event in enumerate(events_value, start=1):
        if not isinstance(event, Mapping):
            raise ArtifactFormatError(f"audit event {index} is not an object")
        events.append(dict(event))

    final_value = value.get("final_response", "")
    if isinstance(final_value, Mapping):
        final_value = final_value.get("final_response", "")
    artifact = ReplayArtifact(
        directory=None,
        run_spec=_mapping_field(value, "run_spec"),
        result=_mapping_field(value, "result"),
        audit_events=tuple(events),
        world_before=_mapping_field(value, "world_before", required=False),
        world_after=_mapping_field(value, "world_after", required=False),
        final_response=str(final_value),
        reader_trace=_optional_mapping_field(value, "reader_trace"),
        action_trace=_optional_mapping_field(value, "action_trace"),
    )
    _validate_artifact(artifact)
    return artifact


def artifact_summary(artifact: ReplayArtifact) -> dict[str, Any]:
    """Build a stable, compact summary without inferring security outcomes."""

    result = artifact.result
    usage = result.get("usage", {})
    if not isinstance(usage, Mapping):
        usage = {}
    return {
        "run_id": artifact.run_id,
        "scenario": artifact.scenario_id,
        "condition": _enum_text(artifact.run_spec.get("content_condition")),
        "defense": _enum_text(artifact.run_spec.get("defense_arm")),
        "seed": artifact.run_spec.get("seed", ""),
        "valid": bool(result.get("valid", False)),
        "invalid_reason": str(result.get("invalid_reason", "")),
        "exposure": bool(result.get("exposure", False)),
        "attempted_attack": bool(result.get("attempted_attack", False)),
        "blocked_attack": bool(result.get("blocked_attack", False)),
        "executed_unauthorized_effect": bool(
            result.get("executed_unauthorized_effect", False)
        ),
        "secret_leakage": bool(result.get("secret_leakage", False)),
        "benign_task_success": bool(result.get("benign_task_success", False)),
        "audit_event_count": len(artifact.audit_events),
        "model_calls": int(usage.get("model_calls", 0) or 0),
        "tool_calls": int(usage.get("tool_calls", 0) or 0),
        "latency_seconds": float(usage.get("latency_seconds", 0.0) or 0.0),
    }


def audit_table(artifact: ReplayArtifact) -> list[list[Any]]:
    """Flatten audit evidence for a human-readable Gradio table."""

    rows: list[list[Any]] = []
    for event in artifact.audit_events:
        provenance = event.get("provenance")
        if not isinstance(provenance, Mapping):
            provenance = {}
        arguments = event.get("arguments", {})
        rows.append(
            [
                event.get("sequence", ""),
                _enum_text(event.get("event_kind")),
                event.get("actor", ""),
                _enum_text(event.get("tool")),
                _enum_text(event.get("decision")),
                event.get("success", ""),
                _enum_text(provenance.get("authority")),
                _enum_text(provenance.get("sensitivity")),
                json.dumps(arguments, ensure_ascii=False, sort_keys=True),
                event.get("reason", ""),
            ]
        )
    return rows


def provenance_edges(artifact: ReplayArtifact) -> list[dict[str, str]]:
    """Extract explicit parent/source links; no textual taint is guessed."""

    edges: list[dict[str, str]] = []
    for event in artifact.audit_events:
        destination = str(event.get("event_id", ""))
        provenance = event.get("provenance")
        if not destination or not isinstance(provenance, Mapping):
            continue
        for relation, field in (
            ("parent", "parent_event_ids"),
            ("source", "source_event_ids"),
        ):
            identifiers = provenance.get(field, ())
            if not isinstance(identifiers, Sequence) or isinstance(identifiers, (str, bytes)):
                continue
            for identifier in identifiers:
                edges.append(
                    {"from": str(identifier), "to": destination, "relation": relation}
                )
    return edges


def world_delta(artifact: ReplayArtifact) -> dict[str, Any]:
    """Describe externally meaningful state changes using exact JSON equality."""

    before = artifact.world_before
    after = artifact.world_after
    return {
        "counts_before": _world_counts(before),
        "counts_after": _world_counts(after),
        "new_outbox_messages": _appended_items(before.get("outbox"), after.get("outbox")),
        "calendar": _mapping_delta(
            before.get("calendar_events"), after.get("calendar_events")
        ),
        "files": _mapping_delta(before.get("files"), after.get("files")),
        "emails": _mapping_delta(before.get("emails"), after.get("emails")),
    }


def _is_attempt_dir(path: Path) -> bool:
    return path.is_dir() and (path / "run_spec.json").is_file() and (
        path / "result.json"
    ).is_file()


def _read_object(path: Path, *, required: bool) -> dict[str, Any]:
    if not path.exists():
        if required:
            raise ArtifactFormatError(f"missing required artifact: {path.name}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactFormatError(f"cannot parse {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactFormatError(f"{path.name} must contain a JSON object")
    return value


def _read_optional_object(path: Path) -> dict[str, Any] | None:
    return _read_object(path, required=False) if path.exists() else None


def _read_jsonl(path: Path) -> tuple[dict[str, Any], ...]:
    if not path.exists():
        return ()
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ArtifactFormatError(f"cannot read {path.name}: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ArtifactFormatError(
                f"cannot parse {path.name} line {line_number}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise ArtifactFormatError(
                f"{path.name} line {line_number} must contain a JSON object"
            )
        events.append(value)
    return tuple(events)


def _validate_artifact(artifact: ReplayArtifact) -> None:
    for field in ("scenario_id", "content_condition", "defense_arm"):
        if field not in artifact.run_spec:
            raise ArtifactFormatError(f"run_spec is missing {field!r}")
    if "valid" not in artifact.result:
        raise ArtifactFormatError("result is missing 'valid'")

    ids = {
        str(value)
        for value in (artifact.run_spec.get("run_id"), artifact.result.get("run_id"))
        if value
    }
    if len(ids) > 1:
        raise ArtifactFormatError("run_spec and result contain different run_id values")

    previous_sequence = 0
    event_ids: set[str] = set()
    for index, event in enumerate(artifact.audit_events, start=1):
        sequence = event.get("sequence")
        if not isinstance(sequence, int) or sequence <= previous_sequence:
            raise ArtifactFormatError(
                f"audit event {index} has a non-increasing integer sequence"
            )
        previous_sequence = sequence
        event_id = event.get("event_id")
        if event_id:
            if event_id in event_ids:
                raise ArtifactFormatError(f"duplicate audit event_id: {event_id}")
            event_ids.add(str(event_id))


def _mapping_field(
    value: Mapping[str, Any], field: str, *, required: bool = True
) -> dict[str, Any]:
    selected = value.get(field)
    if selected is None and not required:
        return {}
    if not isinstance(selected, Mapping):
        raise ArtifactFormatError(f"{field} must be a JSON object")
    return dict(selected)


def _optional_mapping_field(
    value: Mapping[str, Any], field: str
) -> dict[str, Any] | None:
    selected = value.get(field)
    if selected is None:
        return None
    if not isinstance(selected, Mapping):
        raise ArtifactFormatError(f"{field} must be a JSON object")
    return dict(selected)


def _enum_text(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


def _world_counts(world: Mapping[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for field in ("emails", "files", "calendar_events", "outbox"):
        value = world.get(field, {})
        counts[field] = len(value) if isinstance(value, (Mapping, Sequence)) else 0
    return counts


def _appended_items(before: Any, after: Any) -> list[Any]:
    before_items = list(before) if isinstance(before, list) else []
    after_items = list(after) if isinstance(after, list) else []
    if after_items[: len(before_items)] == before_items:
        return after_items[len(before_items) :]
    return after_items


def _mapping_delta(before: Any, after: Any) -> dict[str, list[str]]:
    left = before if isinstance(before, Mapping) else {}
    right = after if isinstance(after, Mapping) else {}
    left_keys = set(str(key) for key in left)
    right_keys = set(str(key) for key in right)
    shared = left_keys & right_keys
    changed = sorted(key for key in shared if left.get(key) != right.get(key))
    return {
        "added": sorted(right_keys - left_keys),
        "removed": sorted(left_keys - right_keys),
        "changed": changed,
    }


__all__ = [
    "ArtifactFormatError",
    "ReplayArtifact",
    "artifact_from_mapping",
    "artifact_summary",
    "audit_table",
    "discover_attempts",
    "load_replay_artifact",
    "provenance_edges",
    "world_delta",
]
