"""Stable, JSON-serialisable contracts shared by the experiment components.

The models in this module are deliberately small and strict.  Persisted records
use tuples rather than mutable lists where practical and reject unknown fields so
that a misspelled policy field cannot silently weaken an experiment.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class Authority(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    DERIVED = "derived"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SECRET = "secret"


class ContentCondition(str, Enum):
    CLEAN = "clean"
    PLACEBO = "placebo"
    ATTACK = "attack"


class DefenseArm(str, Enum):
    ALLOW_ALL = "allow_all"
    PROMPT_ONLY = "prompt_only"
    CAPABILITY_ONLY = "capability_only"
    PROMPT_CAPABILITY_ONLY = "prompt_capability_only"
    FULL = "full"


class ToolName(str, Enum):
    SEARCH_EMAILS = "search_emails"
    READ_EMAIL = "read_email"
    READ_FILE = "read_file"
    SEARCH_CALENDAR = "search_calendar"
    SEND_EMAIL = "send_email"
    CREATE_CALENDAR_EVENT = "create_calendar_event"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class EventKind(str, Enum):
    CONTEXT = "context"
    # Readable alias used by the orchestrator; persisted vocabulary stays "context".
    ACTION_CONTEXT = "context"
    TOOL_PROPOSAL = "tool_proposal"
    POLICY_DECISION = "policy_decision"
    TOOL_EXECUTION = "tool_execution"
    RESOURCE_READ = "resource_read"
    WORLD_MUTATION = "world_mutation"
    TOOL_ERROR = "tool_error"
    INFRASTRUCTURE = "infrastructure"


class ProvenanceLabel(_FrozenModel):
    authority: Authority
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    source_event_ids: tuple[str, ...] = ()
    parent_event_ids: tuple[str, ...] = ()


Scalar = str | int | float | bool


class ParameterBound(_FrozenModel):
    """Constraint for one argument (or the synthetic ``duration_minutes`` key).

    ``minimum``/``maximum`` accept numbers or ISO-8601 date/time strings.  An
    ``allowed_values`` tuple, when supplied, is an exact allow-list.
    """

    allowed_values: tuple[Scalar, ...] | None = None
    minimum: Scalar | None = None
    maximum: Scalar | None = None

    @model_validator(mode="after")
    def require_a_constraint(self) -> "ParameterBound":
        if self.allowed_values is None and self.minimum is None and self.maximum is None:
            raise ValueError("a parameter bound must define allowed_values, minimum, or maximum")
        if self.allowed_values is not None and len(self.allowed_values) == 0:
            raise ValueError("allowed_values cannot be empty")
        return self


class Capability(_FrozenModel):
    capability_id: str
    tool: ToolName
    allowed_resource_ids: tuple[str, ...] | None = None
    allowed_recipients: tuple[str, ...] | None = None
    parameter_bounds: dict[str, ParameterBound] = Field(default_factory=dict)
    max_calls: int = Field(default=1, ge=1)
    max_outbound_sensitivity: Sensitivity = Sensitivity.SECRET

    @field_validator("capability_id")
    @classmethod
    def nonempty_capability_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("capability_id cannot be blank")
        return value


class EmailRecord(_FrozenModel):
    email_id: str
    sender: str
    to: tuple[str, ...]
    subject: str
    body: str
    cc: tuple[str, ...] = ()
    received_at: str = ""
    provenance: ProvenanceLabel = Field(
        default_factory=lambda: ProvenanceLabel(
            authority=Authority.UNTRUSTED, sensitivity=Sensitivity.PUBLIC
        )
    )


class FileRecord(_FrozenModel):
    file_id: str
    name: str
    content: str
    provenance: ProvenanceLabel = Field(
        default_factory=lambda: ProvenanceLabel(
            authority=Authority.TRUSTED, sensitivity=Sensitivity.INTERNAL
        )
    )


class CalendarEvent(_FrozenModel):
    event_id: str
    title: str
    start: str
    end: str
    participants: tuple[str, ...] = ()
    location: str = ""
    provenance: ProvenanceLabel = Field(
        default_factory=lambda: ProvenanceLabel(
            authority=Authority.TRUSTED, sensitivity=Sensitivity.INTERNAL
        )
    )


class SentEmail(_FrozenModel):
    message_id: str
    to: str
    subject: str
    body: str
    cc: tuple[str, ...] = ()


class WorldState(_FrozenModel):
    emails: dict[str, EmailRecord] = Field(default_factory=dict)
    files: dict[str, FileRecord] = Field(default_factory=dict)
    calendar_events: dict[str, CalendarEvent] = Field(default_factory=dict)
    outbox: tuple[SentEmail, ...] = ()

    @model_validator(mode="after")
    def keys_match_resource_ids(self) -> "WorldState":
        collections = (
            ("emails", self.emails, "email_id"),
            ("files", self.files, "file_id"),
            ("calendar_events", self.calendar_events, "event_id"),
        )
        for collection_name, records, id_field in collections:
            for key, record in records.items():
                if key != getattr(record, id_field):
                    raise ValueError(f"{collection_name} key {key!r} does not match record ID")
        return self


class PredicateSpec(_FrozenModel):
    kind: str
    params: dict[str, Any] = Field(default_factory=dict)


class ProtectedValue(_FrozenModel):
    protected_id: str
    value: str
    sensitivity: Sensitivity
    source_resource_id: str

    @field_validator("protected_id", "value", "source_resource_id")
    @classmethod
    def protected_fields_are_nonempty(cls, value: str) -> str:
        if not value:
            raise ValueError("protected value fields cannot be empty")
        return value


class ScenarioSpec(_FrozenModel):
    scenario_id: str
    user_request: str
    initial_world: WorldState
    condition_payloads: dict[ContentCondition, str]
    capabilities: tuple[Capability, ...]
    benign_predicates: tuple[PredicateSpec, ...] = ()
    forbidden_predicates: tuple[PredicateSpec, ...] = ()
    protected_values: tuple[ProtectedValue, ...] = ()

    @model_validator(mode="after")
    def all_conditions_are_present(self) -> "ScenarioSpec":
        missing = set(ContentCondition) - set(self.condition_payloads)
        if missing:
            names = ", ".join(sorted(item.value for item in missing))
            raise ValueError(f"missing condition payloads: {names}")
        return self


class RunSpec(_FrozenModel):
    scenario_id: str
    content_condition: ContentCondition
    defense_arm: DefenseArm
    seed: int
    repetition: int = Field(ge=0)
    model_config_hash: str
    run_id: str = ""

    @model_validator(mode="before")
    @classmethod
    def derive_run_id(cls, data: Any) -> Any:
        if not isinstance(data, dict) or data.get("run_id"):
            return data
        fields = (
            str(data.get("scenario_id", "")),
            str(getattr(data.get("content_condition"), "value", data.get("content_condition", ""))),
            str(getattr(data.get("defense_arm"), "value", data.get("defense_arm", ""))),
            str(data.get("seed", "")),
            str(data.get("repetition", "")),
            str(data.get("model_config_hash", "")),
        )
        digest = hashlib.sha256("\x1f".join(fields).encode("utf-8")).hexdigest()[:16]
        return {**data, "run_id": f"run-{digest}"}


class AuditEvent(_FrozenModel):
    sequence: int = Field(ge=1)
    event_id: str
    event_kind: EventKind
    actor: str
    tool: ToolName | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    resource_ids: tuple[str, ...] = ()
    provenance: ProvenanceLabel | None = None
    decision: Decision | None = None
    reason: str = ""
    success: bool | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("audit timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class UsageStats(_FrozenModel):
    reader_prompt_tokens: int = Field(default=0, ge=0)
    reader_completion_tokens: int = Field(default=0, ge=0)
    action_prompt_tokens: int = Field(default=0, ge=0)
    action_completion_tokens: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    latency_seconds: float = Field(default=0.0, ge=0.0)


class RunResult(_FrozenModel):
    run_id: str
    valid: bool
    invalid_reason: str = ""
    exposure: bool = False
    attempted_attack: bool = False
    blocked_attack: bool = False
    executed_unauthorized_effect: bool = False
    secret_leakage: bool = False
    benign_task_success: bool = False
    benign_block: bool = False
    process_exit_code: int | None = None
    model_error: str = ""
    usage: UsageStats = Field(default_factory=UsageStats)
    artifact_paths: dict[str, str] = Field(default_factory=dict)

    @field_validator("artifact_paths")
    @classmethod
    def artifact_paths_must_be_relative(cls, paths: dict[str, str]) -> dict[str, str]:
        for label, path in paths.items():
            parsed = PurePosixPath(path)
            if parsed.is_absolute() or ".." in parsed.parts:
                raise ValueError(f"artifact path {label!r} must be relative and cannot contain '..'")
        return paths


def stable_model_hash(value: BaseModel | dict[str, Any]) -> str:
    """Return a reproducible SHA-256 over a model/configuration object."""

    data = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
