"""Explicit, append-only attempt accounting for external benchmarks.

The native benchmark runner deliberately does not guess which attempt is
"best".  This module records the initial attempt for every frozen plan row,
and permits exactly one recovery attempt when the initial outcome is a
declared infrastructure interruption.  The resulting JSON is portable across
benchmarks and can be inspected without importing the benchmark package.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .agentdojo_external import AgentDojoResultRecord, AgentDojoRunSpec


class AttemptStatus(str, Enum):
    """State of an append-only attempt leaf."""

    COMPLETE = "complete"
    MISSING = "missing"
    INVALID = "invalid"


INFRASTRUCTURE_REASONS = frozenset(
    {
        "model_timeout",
        "local_endpoint_transport_failure",
        "scheduler_termination",
        "artifact_write_interruption",
    }
)

# A few callers use the controller's older labels.  They normalize to the
# frozen native label, but are not accepted as a persisted reason by default.
_REASON_ALIASES = {
    "model_http_error": "local_endpoint_transport_failure",
    "local_endpoint_server_failure": "local_endpoint_transport_failure",
    "truncated_transport": "local_endpoint_transport_failure",
}
ATTEMPT_IDS = ("attempt-0001", "attempt-0002")
_HEX64 = set("0123456789abcdef")


def normalize_infrastructure_reason(reason: str) -> str:
    """Normalize a declared interruption reason, rejecting behavior outcomes."""

    value = str(reason or "").strip()
    value = _REASON_ALIASES.get(value, value)
    if value not in INFRASTRUCTURE_REASONS:
        raise ValueError(f"unregistered attempt interruption reason: {reason!r}")
    return value


def _hash_is_valid(value: str) -> bool:
    return len(value) == 64 and not (set(value) - _HEX64)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class AttemptSelection(_FrozenModel):
    """One planned run's initial/recovery state and explicit selected record.

    ``initial_attempt`` is intentionally fixed.  A missing initial record is
    represented instead of silently disappearing from the denominator.  A
    recovery can only point at ``attempt-0002`` and must carry a declared
    infrastructure reason and a complete record hash.
    """

    run_id: str
    initial_attempt: Literal["attempt-0001"] = "attempt-0001"
    initial_status: AttemptStatus
    initial_record_sha256: str = ""
    initial_reason: str = ""
    recovered_attempt: Literal["attempt-0002"] | None = None
    recovered_status: AttemptStatus | None = None
    recovered_record_sha256: str = ""
    recovered_reason: str = ""
    selected_attempt: Literal["attempt-0001", "attempt-0002"] | None = None
    selected_record_sha256: str = ""
    # The logical values below are the conservative ITT projection for an
    # incomplete selected record.  For a complete record they equal the
    # official values and are still persisted for analysis provenance.
    conservative_utility: bool | None = None
    conservative_targeted_attack_success: bool | None = None

    @field_validator("run_id")
    @classmethod
    def nonempty_run_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("run_id cannot be blank")
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("run_id must be one path component")
        return value

    @field_validator(
        "initial_record_sha256", "recovered_record_sha256", "selected_record_sha256"
    )
    @classmethod
    def valid_hash_or_empty(cls, value: str) -> str:
        if value and not _hash_is_valid(value):
            raise ValueError("record hashes must be lowercase SHA-256 hex digests")
        return value

    @field_validator("initial_reason", "recovered_reason")
    @classmethod
    def clean_reason(cls, value: str) -> str:
        return str(value or "").strip()

    @model_validator(mode="after")
    def validate_selection(self) -> "AttemptSelection":
        if self.initial_status in {AttemptStatus.COMPLETE, AttemptStatus.INVALID} and not self.initial_record_sha256:
            raise ValueError("present initial attempts require initial_record_sha256")
        if self.initial_status == AttemptStatus.MISSING and self.initial_record_sha256:
            raise ValueError("missing initial attempts cannot have a record hash")

        if self.recovered_attempt is None:
            if self.recovered_status is not None or self.recovered_record_sha256:
                raise ValueError("recovery fields require recovered_attempt=attempt-0002")
            if self.recovered_reason:
                raise ValueError("recovered_reason requires recovered_attempt=attempt-0002")
        else:
            if self.initial_status == AttemptStatus.COMPLETE:
                raise ValueError("a valid initial attempt cannot have a recovery")
            if not self.recovered_reason:
                raise ValueError("recovered attempt requires a declared infrastructure reason")
            normalize_infrastructure_reason(self.recovered_reason)
            if self.recovered_status in {AttemptStatus.COMPLETE, AttemptStatus.INVALID} and not self.recovered_record_sha256:
                raise ValueError("present recovered attempts require recovered_record_sha256")
            if self.recovered_status == AttemptStatus.MISSING and self.recovered_record_sha256:
                raise ValueError("missing recovered attempts cannot have a record hash")

        if self.selected_attempt is None:
            if self.selected_record_sha256:
                raise ValueError("selected_record_sha256 requires selected_attempt")
        elif self.selected_attempt == "attempt-0001":
            if self.initial_status not in {AttemptStatus.COMPLETE, AttemptStatus.INVALID}:
                raise ValueError("selected initial attempt must be present")
            if self.selected_record_sha256 != self.initial_record_sha256:
                raise ValueError("selected hash must match selected initial record")
        elif self.selected_attempt == "attempt-0002":
            if self.recovered_attempt != "attempt-0002" or self.recovered_status != AttemptStatus.COMPLETE:
                raise ValueError("selected recovery must be one complete attempt-0002")
            if self.selected_record_sha256 != self.recovered_record_sha256:
                raise ValueError("selected hash must match selected recovered record")
        return self

    @property
    def selected_hash(self) -> str:
        return self.selected_record_sha256

    @property
    def itt_utility(self) -> bool | None:
        return self.conservative_utility

    @property
    def itt_targeted_attack_success(self) -> bool | None:
        return self.conservative_targeted_attack_success

    @property
    def initial_complete(self) -> bool:
        return self.initial_status == AttemptStatus.COMPLETE

    @property
    def recovered_complete(self) -> bool:
        return self.recovered_status == AttemptStatus.COMPLETE


class AttemptSelectionManifest(_FrozenModel):
    """A complete, one-row-per-run selection manifest."""

    schema_version: Literal["1"] = "1"
    plan_sha256: str
    rows: tuple[AttemptSelection, ...]

    @model_validator(mode="before")
    @classmethod
    def aliases(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            data = dict(value)
            if "rows" not in data and "selections" in data:
                data["rows"] = data.pop("selections")
            return data
        return value

    @field_validator("plan_sha256")
    @classmethod
    def valid_plan_hash(cls, value: str) -> str:
        if not _hash_is_valid(value):
            raise ValueError("plan_sha256 must be a lowercase SHA-256 hex digest")
        return value

    @model_validator(mode="after")
    def validate_rows(self) -> "AttemptSelectionManifest":
        run_ids = [row.run_id for row in self.rows]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("duplicate run IDs in attempt selection manifest")
        if not run_ids:
            raise ValueError("attempt selection manifest requires at least one planned run")
        return self

    @property
    def selections(self) -> tuple[AttemptSelection, ...]:
        return self.rows

    def for_run(self, run_id: str) -> AttemptSelection:
        for row in self.rows:
            if row.run_id == run_id:
                return row
        raise KeyError(run_id)


def record_sha256(path: str | Path) -> str:
    """Hash an immutable record file."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def plan_sha256(plan_path: str | Path) -> str:
    return record_sha256(plan_path)


def _load_plan(plan: Sequence[AgentDojoRunSpec | Mapping[str, Any]] | str | Path) -> list[AgentDojoRunSpec]:
    if isinstance(plan, (str, Path)):
        rows = []
        for line in Path(plan).read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(AgentDojoRunSpec.model_validate(json.loads(line)))
        return rows
    return [AgentDojoRunSpec.model_validate(row) for row in plan]


def _load_record(path: Path, expected: AgentDojoRunSpec) -> tuple[AgentDojoResultRecord, str]:
    record = AgentDojoResultRecord.model_validate(json.loads(path.read_text(encoding="utf-8")))
    expected_record = record.run_spec
    if record.attempt_id != path.parent.name:
        raise ValueError(f"record attempt_id does not match artifact path for {expected.run_id}")
    if expected_record != expected:
        raise ValueError(f"record run spec does not match frozen plan row {expected.run_id}")
    return record, record_sha256(path)


def _interruption_reason(interruptions: Mapping[str, Any] | None, run_id: str) -> str:
    if not interruptions:
        return ""
    raw: Any = interruptions.get(run_id, "")
    if isinstance(raw, Mapping):
        raw = raw.get("reason", raw.get("invalid_reason", ""))
    return normalize_infrastructure_reason(str(raw)) if raw else ""


def build_attempt_selection(
    plan: Sequence[AgentDojoRunSpec | Mapping[str, Any]] | str | Path,
    artifact_root: str | Path,
    *,
    interruptions: Mapping[str, Any] | None = None,
    plan_digest: str | None = None,
    allow_extra_runs: bool = False,
) -> AttemptSelectionManifest:
    """Build a deterministic manifest from declared records, never inferring success."""

    rows = _load_plan(plan)
    if not rows:
        raise ValueError("frozen plan is empty")
    run_ids = [row.run_id for row in rows]
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("duplicate run IDs in frozen plan")
    root = Path(artifact_root)
    expected_run_ids = set(run_ids)
    if root.exists():
        extras = sorted(
            item.name for item in root.iterdir()
            if item.is_dir() and item.name not in expected_run_ids and item.name != "official-traces"
        )
        if extras and not allow_extra_runs:
            raise ValueError(f"artifact records contain run IDs missing from frozen plan: {extras!r}")
    selections: list[AttemptSelection] = []
    for spec in rows:
        run_root = root / spec.run_id
        if run_root.is_dir():
            attempt_dirs = {item.name for item in run_root.iterdir() if item.is_dir()}
            unexpected_attempts = sorted(attempt_dirs - {"attempt-0001", "attempt-0002"})
            if unexpected_attempts:
                raise ValueError(f"more than one retry or unregistered attempt for {spec.run_id}: {unexpected_attempts!r}")
        initial_path = run_root / "attempt-0001" / "record.json"
        recovery_path = run_root / "attempt-0002" / "record.json"
        initial_record: AgentDojoResultRecord | None = None
        initial_hash = ""
        initial_reason = ""
        if initial_path.is_file():
            try:
                initial_record, initial_hash = _load_record(initial_path, spec)
                initial_status = AttemptStatus.COMPLETE if initial_record.valid else AttemptStatus.INVALID
                initial_reason = initial_record.invalid_reason or initial_record.error
            except Exception as exc:  # retain evidence but do not select malformed data
                initial_status = AttemptStatus.INVALID
                initial_hash = record_sha256(initial_path)
                initial_reason = f"record_schema_error: {type(exc).__name__}: {exc}"
        else:
            initial_status = AttemptStatus.MISSING
            initial_reason = _interruption_reason(interruptions, spec.run_id)
            if not initial_reason:
                initial_reason = "missing_initial_record"

        recovery_reason = ""
        recovery_record: AgentDojoResultRecord | None = None
        recovery_hash = ""
        if initial_record is not None and initial_record.invalid_reason:
            try:
                recovery_reason = normalize_infrastructure_reason(initial_record.invalid_reason)
            except ValueError:
                recovery_reason = ""
        # Scheduler declarations are authoritative only when no initial
        # wrapper exists.  A behavioral invalid reason on an existing record
        # must not be overwritten by an unrelated scheduler label.
        if (
            not recovery_reason
            and (
                initial_status == AttemptStatus.MISSING
                or initial_reason.startswith("record_schema_error:")
            )
        ):
            recovery_reason = _interruption_reason(interruptions, spec.run_id)
        if recovery_path.exists() and not recovery_reason:
            raise ValueError(f"attempt-0002 exists without a declared infrastructure reason for {spec.run_id}")
        if recovery_reason and recovery_path.exists():
            try:
                recovery_record, recovery_hash = _load_record(recovery_path, spec)
                recovery_status = AttemptStatus.COMPLETE if recovery_record.valid else AttemptStatus.INVALID
            except Exception:
                recovery_status = AttemptStatus.INVALID
                recovery_hash = record_sha256(recovery_path)
        elif recovery_reason:
            recovery_status = AttemptStatus.MISSING
        else:
            recovery_status = None

        selected_attempt: Literal["attempt-0001", "attempt-0002"] | None = None
        selected_hash = ""
        selected_record = initial_record
        if initial_record is not None:
            selected_attempt = "attempt-0001"
            selected_hash = initial_hash
        if (
            selected_attempt == "attempt-0001"
            and initial_record is not None
            and initial_record.invalid_reason
            and recovery_reason
            and recovery_status == AttemptStatus.COMPLETE
            and recovery_record is not None
        ) or (
            selected_attempt is None
            and recovery_status == AttemptStatus.COMPLETE
            and recovery_record is not None
        ):
            selected_attempt = "attempt-0002"
            selected_hash = recovery_hash
            selected_record = recovery_record

        attacked = spec.attack != "none"
        infra_invalid = False
        if selected_record is not None and not selected_record.valid:
            try:
                normalize_infrastructure_reason(selected_record.invalid_reason)
                infra_invalid = True
            except ValueError:
                infra_invalid = False
        if selected_record is not None and not infra_invalid:
            utility = selected_record.utility
            attack_success = selected_record.targeted_attack_success
        else:
            # Conservative ITT: unresolved attacked cells count as attack
            # success and utility failure; clean cells only count utility fail.
            utility = False
            attack_success = True if attacked else None
        selections.append(
            AttemptSelection(
                run_id=spec.run_id,
                initial_status=initial_status,
                initial_record_sha256=initial_hash,
                initial_reason=initial_reason,
                recovered_attempt="attempt-0002" if recovery_reason else None,
                recovered_status=recovery_status,
                recovered_record_sha256=recovery_hash,
                recovered_reason=recovery_reason,
                selected_attempt=selected_attempt,
                selected_record_sha256=selected_hash,
                conservative_utility=utility,
                conservative_targeted_attack_success=attack_success,
            )
        )
    if plan_digest is None:
        if isinstance(plan, (str, Path)):
            plan_digest = plan_sha256(plan)
        else:
            payload = "\n".join(row.model_dump_json() for row in rows) + "\n"
            plan_digest = hashlib.sha256(payload.encode()).hexdigest()
    return AttemptSelectionManifest(plan_sha256=plan_digest, rows=tuple(selections))


def write_manifest_exclusive(manifest: AttemptSelectionManifest, output: str | Path) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(manifest.model_dump_json(indent=2))
        handle.write("\n")


__all__ = [
    "ATTEMPT_IDS",
    "INFRASTRUCTURE_REASONS",
    "AttemptSelection",
    "AttemptSelectionManifest",
    "AttemptStatus",
    "build_attempt_selection",
    "normalize_infrastructure_reason",
    "plan_sha256",
    "record_sha256",
    "write_manifest_exclusive",
]
