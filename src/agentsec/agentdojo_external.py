"""Project-owned contracts for the native AgentDojo external slice.

This module deliberately has no dependency on AgentDojo.  Enumeration and
execution adapters can import these small, frozen contracts in either the
controller environment or the isolated AgentDojo environment.  Pair
selection is outcome-independent: it only uses the public benchmark task
identifiers and their canonical hashes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


AGENTDOJO_SUITES = ("workspace", "travel", "banking", "slack")
CANONICAL_ATTACKS = ("important_instructions", "tool_knowledge")
DEFENSES = ("none", "repeat_user_prompt")
TRANSFER_DEFENSES = (
    "none",
    "repeat_user_prompt",
    "capability_only",
    "provenance_only",
    "prompt_capability",
    "prompt_provenance",
    "full",
)
_PAIR_KEY_PREFIX = "workspace:v1.2.2:"
_ATTACKS = CANONICAL_ATTACKS
_DEFENSES = DEFENSES
_HEX64 = set("0123456789abcdef")


def _parse_canonical_pair_key(value: str) -> tuple[str, str, str]:
    """Parse a suite-qualified canonical key."""

    parts = value.split(":", 3)
    if len(parts) != 4 or parts[1] != "v1.2.2" or parts[0] not in AGENTDOJO_SUITES:
        raise ValueError("manifest pair IDs must use <suite>:v1.2.2 prefix")
    suite, _version, user_id, injection_id = parts
    if not user_id or not injection_id or ":" in user_id or ":" in injection_id:
        raise ValueError("canonical pair IDs require nonempty user and injection IDs")
    return suite, user_id, injection_id


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )


class AgentDojoPair(_FrozenModel):
    """One outcome-independent, pre-screened native benchmark pair."""

    suite: str = "workspace"
    canonical_key: str
    canonical_sha256: str
    user_task_id: str
    injection_task_id: str
    runnable: bool
    exclusion_reason: str = ""

    @field_validator("suite")
    @classmethod
    def require_suite(cls, value: str) -> str:
        if value not in AGENTDOJO_SUITES:
            raise ValueError(f"unsupported AgentDojo suite: {value}")
        return value

    @field_validator("canonical_key", "user_task_id", "injection_task_id")
    @classmethod
    def require_nonempty_identifier(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("AgentDojo identifiers cannot be blank")
        return value

    @field_validator("canonical_sha256")
    @classmethod
    def require_sha256(cls, value: str) -> str:
        if len(value) != 64 or any(char not in _HEX64 for char in value):
            raise ValueError("canonical_sha256 must be a lowercase SHA-256 hex digest")
        return value

    @model_validator(mode="after")
    def enforce_canonical_identity(self) -> "AgentDojoPair":
        parsed_suite, parsed_user, parsed_injection = _parse_canonical_pair_key(self.canonical_key)
        if (parsed_suite, parsed_user, parsed_injection) != (self.suite, self.user_task_id, self.injection_task_id):
            raise ValueError("canonical_key does not match the suite:v1.2.2 pair identity")
        expected_hash = hashlib.sha256(self.canonical_key.encode("utf-8")).hexdigest()
        if self.canonical_sha256 != expected_hash:
            raise ValueError("canonical_sha256 does not match canonical_key")
        return self


class AgentDojoRunSpec(_FrozenModel):
    """One cell in the development or formal native AgentDojo matrix."""

    suite: str = "workspace"
    phase: Literal["development", "formal"]
    user_task_id: str
    injection_task_id: str | None
    attack: str
    defense: str
    model_config_hash: str
    run_id: str = ""

    @field_validator("suite")
    @classmethod
    def require_suite(cls, value: str) -> str:
        if value not in AGENTDOJO_SUITES:
            raise ValueError(f"unsupported AgentDojo suite: {value}")
        return value

    @field_validator("attack")
    @classmethod
    def require_attack(cls, value: str) -> str:
        if value != "none" and value not in CANONICAL_ATTACKS:
            raise ValueError(f"unsupported AgentDojo attack: {value}")
        return value

    @field_validator("defense")
    @classmethod
    def require_defense(cls, value: str) -> str:
        if value not in TRANSFER_DEFENSES:
            raise ValueError(f"unsupported AgentDojo defense: {value}")
        return value

    @field_validator("user_task_id")
    @classmethod
    def require_user_task_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("user_task_id cannot be blank")
        return value

    @field_validator("injection_task_id")
    @classmethod
    def require_injection_task_id_when_present(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("injection_task_id cannot be blank")
        return value

    @field_validator("model_config_hash")
    @classmethod
    def require_model_config_hash(cls, value: str) -> str:
        if len(value) != 64 or any(char not in _HEX64 for char in value):
            raise ValueError("model_config_hash must be a lowercase SHA-256 hex digest")
        return value

    @model_validator(mode="after")
    def enforce_clean_cell_shape(self) -> "AgentDojoRunSpec":
        if self.attack == "none" and self.injection_task_id is not None:
            raise ValueError("clean AgentDojo cells must not have an injection_task_id")
        if self.attack != "none" and self.injection_task_id is None:
            raise ValueError("attacked AgentDojo cells require an injection_task_id")
        return self

    @model_validator(mode="before")
    @classmethod
    def derive_run_id(cls, value: Any) -> Any:
        if not isinstance(value, dict) or value.get("run_id"):
            return value
        fields = (
            value.get("phase", ""),
            value.get("suite", "workspace"),
            value.get("user_task_id", ""),
            value.get("injection_task_id") or "none",
            value.get("attack", ""),

            value.get("defense", ""),
        )
        digest = hashlib.sha256("\x1f".join(str(field) for field in fields).encode()).hexdigest()[:16]
        return {**value, "run_id": f"adj-{digest}"}


class AgentDojoResultRecord(_FrozenModel):
    """Project-owned wrapper around one untouched AgentDojo result."""

    suite: str = "workspace"
    phase: Literal["development", "formal"]
    user_task_id: str
    injection_task_id: str | None
    attack: str
    defense: str
    model_config_hash: str
    run_id: str
    attempt_id: Literal["attempt-0001", "attempt-0002"]
    valid: bool
    invalid_reason: str = ""
    utility: bool | None = None
    targeted_attack_success: bool | None = None
    official_security_value: bool | None = None
    official_trace_path: str = ""
    trace_sha256: str = ""
    duration_seconds: float = Field(default=0.0, ge=0.0)
    error: str = ""
    adapter_mode: str = ""
    adapter_denied_calls: int = Field(default=0, ge=0)
    adapter_decision_sha256: str = ""

    @model_validator(mode="before")
    @classmethod
    def unpack_run_spec(cls, value: Any) -> Any:
        if not isinstance(value, Mapping) or "run_spec" not in value:
            return value
        data = dict(value)
        nested = data.pop("run_spec")
        nested_data = nested.model_dump() if isinstance(nested, AgentDojoRunSpec) else dict(nested)
        for key, item in nested_data.items():
            data.setdefault(key, item)
        return data

    @field_validator("run_id", "user_task_id")
    @classmethod
    def nonempty_ids(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("AgentDojo result identifiers cannot be blank")
        return value

    @field_validator("suite")
    @classmethod
    def require_suite(cls, value: str) -> str:
        if value not in AGENTDOJO_SUITES:
            raise ValueError(f"unsupported AgentDojo suite: {value}")
        return value

    @field_validator("attack")
    @classmethod
    def require_attack(cls, value: str) -> str:
        if value != "none" and value not in CANONICAL_ATTACKS:
            raise ValueError(f"unsupported AgentDojo attack: {value}")
        return value

    @field_validator("defense")
    @classmethod
    def require_defense(cls, value: str) -> str:
        if value not in TRANSFER_DEFENSES:
            raise ValueError(f"unsupported AgentDojo defense: {value}")
        return value

    @field_validator("injection_task_id")
    @classmethod
    def valid_injection_id(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("injection_task_id cannot be blank")
        return value

    @field_validator("model_config_hash")
    @classmethod
    def valid_model_hash(cls, value: str) -> str:
        if len(value) != 64 or any(char not in _HEX64 for char in value):
            raise ValueError("model_config_hash must be a lowercase SHA-256 hex digest")
        return value

    @field_validator("trace_sha256")
    @classmethod
    def valid_trace_hash(cls, value: str) -> str:
        if value and (len(value) != 64 or any(char not in _HEX64 for char in value)):
            raise ValueError("trace_sha256 must be a lowercase SHA-256 hex digest")
        return value

    @field_validator("attempt_id")
    @classmethod
    def valid_attempt(cls, value: str) -> str:
        if value not in {"attempt-0001", "attempt-0002"}:
            raise ValueError("attempt_id must be attempt-0001 or attempt-0002")
        return value

    @model_validator(mode="after")
    def validate_metric_semantics(self) -> "AgentDojoResultRecord":
        if self.attack == "none":
            if self.injection_task_id is not None:
                raise ValueError("clean AgentDojo result cannot have injection_task_id")
            if self.targeted_attack_success is not None:
                raise ValueError("clean AgentDojo result must have targeted_attack_success=None")
            if self.official_security_value is not None:
                raise ValueError("clean AgentDojo result must have official_security_value=None")
        else:
            if self.injection_task_id is None:
                raise ValueError("attacked AgentDojo result requires injection_task_id")
            if self.targeted_attack_success != self.official_security_value:
                raise ValueError("targeted_attack_success must equal official_security_value for attacked cells")
        if self.valid and self.invalid_reason:
            raise ValueError("valid AgentDojo result cannot carry invalid_reason")
        if self.valid and self.error:
            raise ValueError("non-empty AgentDojo error must make the result invalid")
        if not self.valid and not self.invalid_reason and not self.error:
            raise ValueError("invalid AgentDojo result requires invalid_reason or error")
        return self

    @property
    def run_spec(self) -> AgentDojoRunSpec:
        return AgentDojoRunSpec(
            suite=self.suite,
            phase=self.phase,
            user_task_id=self.user_task_id,
            injection_task_id=self.injection_task_id,
            attack=self.attack,
            defense=self.defense,
            model_config_hash=self.model_config_hash,
            run_id=self.run_id,
        )

    @property
    def security(self) -> bool | None:
        return self.official_security_value


class AgentDojoFrozenManifest(_FrozenModel):
    """Identity and coverage record written alongside frozen JSONL plans."""

    schema_version: Literal["1"] = "1"
    agentdojo_commit: Literal["a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"]
    agentdojo_tag: Literal["v0.1.35"]
    benchmark_version: Literal["v1.2.2"]
    suite: Literal["workspace"]
    source_sha256: str
    # Immutable VCS identity recorded by the isolated AgentDojo freeze.
    agentdojo_source_commit: str = ""
    config_sha256: str
    model_config_hash: str
    served_model_name: str
    model_checkpoint_path: str = Field(
        validation_alias=AliasChoices("model_checkpoint_path", "model_path")
    )
    model_checkpoint_sha256: str
    selected_pair_ids: tuple[str, ...] = Field(
        validation_alias=AliasChoices("selected_pair_ids", "selected_pair_keys")
    )
    development_pair_ids: tuple[str, ...] = Field(
        validation_alias=AliasChoices("development_pair_ids", "development_pair_keys")
    )
    formal_pair_ids: tuple[str, ...] = Field(
        validation_alias=AliasChoices("formal_pair_ids", "formal_pair_keys")
    )
    development_plan_sha256: str
    formal_plan_sha256: str
    selected_pair_count: int = Field(ge=0)
    development_pair_count: int = Field(
        ge=0,
        validation_alias=AliasChoices("development_pair_count", "development_count"),
    )
    formal_pair_count: int = Field(
        ge=0,
        validation_alias=AliasChoices("formal_pair_count", "formal_count"),
    )
    formal_attacked_count: int = Field(ge=0)
    formal_clean_count: int = Field(ge=0)
    formal_total_count: int = Field(ge=0)
    # Optional digests keep older fixtures valid while freezing every artifact.
    screening_sha256: str = ""
    selected_pairs_sha256: str = ""
    environment_sha256: str = ""
    screened_pair_count: int = Field(default=0, ge=0)


    @field_validator(
        "source_sha256",
        "config_sha256",
        "model_config_hash",
        "model_checkpoint_sha256",
        "development_plan_sha256",
        "formal_plan_sha256",
        "screening_sha256",
        "selected_pairs_sha256",
        "environment_sha256",
    )
    @classmethod
    def require_sha256(cls, value: str) -> str:
        if value == "":
            return value
        if len(value) != 64 or any(char not in _HEX64 for char in value):
            raise ValueError("manifest hashes must be lowercase SHA-256 hex digests")
        return value

    @field_validator("served_model_name", "model_checkpoint_path")
    @classmethod
    def require_model_identity(cls, value: str, info: Any) -> str:
        if not value.strip():
            raise ValueError("model identity fields cannot be blank")
        if info.field_name == "model_checkpoint_path" and not value.startswith("/"):
            raise ValueError("model_checkpoint_path must be absolute")
        return value

    @field_validator("selected_pair_ids", "development_pair_ids", "formal_pair_ids")
    @classmethod
    def require_unique_canonical_pair_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("manifest pair IDs must be unique")
        if any(not item.strip() for item in value):
            raise ValueError("manifest pair IDs cannot be blank")
        for item in value:
            _parse_canonical_pair_key(item)
        return value

    @model_validator(mode="after")
    def validate_manifest_coverage(self) -> "AgentDojoFrozenManifest":
        if self.selected_pair_count != 18:
            raise ValueError("selected_pair_count must be exactly 18")
        if self.development_pair_count != 2:
            raise ValueError("development_pair_count must be exactly 2")
        if self.formal_pair_count != 16:
            raise ValueError("formal_pair_count must be exactly 16")
        if len(self.selected_pair_ids) != 18:
            raise ValueError("selected_pair_ids must contain exactly 18 canonical keys")
        if self.development_pair_count != len(self.development_pair_ids):
            raise ValueError("development_pair_count does not match development_pair_ids")
        if self.formal_pair_count != len(self.formal_pair_ids):
            raise ValueError("formal_pair_count does not match formal_pair_ids")
        selected = set(self.selected_pair_ids)
        development = set(self.development_pair_ids)
        formal = set(self.formal_pair_ids)
        if development & formal:
            raise ValueError("development and formal pair partitions must be disjoint")
        if development | formal != selected:
            raise ValueError("development/formal pair IDs must partition selected_pair_ids")
        if self.development_pair_ids != self.selected_pair_ids[:2]:
            raise ValueError("the first two selected pair IDs must be the development partition")
        if self.formal_pair_ids != self.selected_pair_ids[2:]:
            raise ValueError("selected pair IDs after the first two must be the formal partition")
        if self.formal_attacked_count != self.formal_pair_count * 4:
            raise ValueError("formal_attacked_count must be four cells per formal pair")
        if self.formal_total_count != self.formal_attacked_count + self.formal_clean_count:
            raise ValueError("formal_total_count must equal formal_attacked_count + formal_clean_count")
        if self.formal_total_count > 96:
            raise ValueError("formal_total_count cannot exceed 96 native AgentDojo calls")
        if self.formal_clean_count > self.formal_pair_count * 2:
            raise ValueError("formal_clean_count cannot exceed two clean cells per formal pair")
        return self

    @property
    def development_pair_keys(self) -> tuple[str, ...]:
        """Backward-compatible spelling used by early freeze drafts."""

        return self.development_pair_ids

    @property
    def formal_pair_keys(self) -> tuple[str, ...]:
        """Backward-compatible spelling used by early freeze drafts."""

        return self.formal_pair_ids


def validate_agentdojo_model_binding(
    manifest: AgentDojoFrozenManifest | None,
    model_config_hash: str,
    served_model_name: str,
    model_checkpoint_path: str,
    model_checkpoint_sha256: str,
) -> None:
    """Reject execution when the victim identity differs from the freeze.

    A manifest compares runtime identity against the frozen values.  When no
    manifest is available, all four explicit identity values are still
    validated, so callers cannot silently omit a checkpoint fingerprint.
    """

    expected_hash = _require_model_config_hash(model_config_hash)
    if not served_model_name.strip():
        raise ValueError("served_model_name cannot be blank")
    if not model_checkpoint_path.startswith("/"):
        raise ValueError("model_checkpoint_path must be absolute")
    _require_sha256(model_checkpoint_sha256, "model_checkpoint_sha256")
    if manifest is None:
        return
    if manifest.model_config_hash != expected_hash:
        raise ValueError("AgentDojo manifest model_config_hash mismatch")
    if manifest.served_model_name != served_model_name:
        raise ValueError("AgentDojo manifest served_model_name mismatch")
    if manifest.model_checkpoint_path != model_checkpoint_path:
        raise ValueError("AgentDojo manifest model_checkpoint_path mismatch")
    if manifest.model_checkpoint_sha256 != model_checkpoint_sha256:
        raise ValueError("AgentDojo manifest model_checkpoint_sha256 mismatch")


def canonical_pair(user_task_id: str, injection_task_id: str, suite_name: str = "workspace") -> AgentDojoPair:
    """Create the frozen canonical representation for one benchmark pair."""

    if suite_name not in AGENTDOJO_SUITES:
        raise ValueError(f"unsupported AgentDojo suite: {suite_name}")
    key = f"{suite_name}:v1.2.2:{user_task_id}:{injection_task_id}"
    return AgentDojoPair(
        suite=suite_name,
        canonical_key=key,
        canonical_sha256=hashlib.sha256(key.encode("utf-8")).hexdigest(),
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        runnable=True,
    )


def _coerce_pair(candidate: AgentDojoPair | Mapping[str, Any] | Any) -> AgentDojoPair:
    if isinstance(candidate, AgentDojoPair):
        return candidate
    if isinstance(candidate, Mapping):
        data = dict(candidate)
    else:
        data = {
            field: getattr(candidate, field)
            for field in (
                "suite",
                "canonical_key",
                "canonical_sha256",
                "user_task_id",
                "injection_task_id",
                "runnable",
                "exclusion_reason",
            )
            if hasattr(candidate, field)
        }
    if "user_task_id" not in data or "injection_task_id" not in data:
        raise TypeError("each AgentDojo candidate must provide user_task_id and injection_task_id")
    if "canonical_key" not in data or "canonical_sha256" not in data:
        generated = canonical_pair(str(data["user_task_id"]), str(data["injection_task_id"]))
        data = {
            **generated.model_dump(),
            **data,
        }
    return AgentDojoPair.model_validate(data)


def select_agentdojo_pairs(
    candidates: Iterable[AgentDojoPair | Mapping[str, Any] | Any],
) -> list[AgentDojoPair]:
    """Select exactly 18 runnable pairs with deterministic three-pass diversity.

    Candidates are sorted by canonical hash before all passes.  Pass one adds
    pairs whose user and injection IDs are both unseen; pass two adds pairs
    with at least one unseen ID; pass three fills the remaining slots in hash
    order.  There is intentionally no random seed or model-dependent input.
    """

    normalized = [_coerce_pair(candidate) for candidate in candidates]
    seen_keys: set[str] = set()
    for pair in normalized:
        if pair.canonical_key in seen_keys:
            raise ValueError(f"duplicate AgentDojo pair: {pair.canonical_key}")
        seen_keys.add(pair.canonical_key)
    runnable = [pair for pair in normalized if pair.runnable]
    if len(runnable) < 18:
        raise ValueError("at least 18 runnable AgentDojo pairs are required")
    ordered = sorted(runnable, key=lambda pair: (pair.canonical_sha256, pair.canonical_key))
    selected: list[AgentDojoPair] = []
    selected_keys: set[str] = set()
    seen_users: set[str] = set()
    seen_injections: set[str] = set()

    def add(pair: AgentDojoPair) -> None:
        if len(selected) >= 18 or pair.canonical_key in selected_keys:
            return
        selected.append(pair)
        selected_keys.add(pair.canonical_key)
        seen_users.add(pair.user_task_id)
        seen_injections.add(pair.injection_task_id)

    for pair in ordered:
        if pair.user_task_id not in seen_users and pair.injection_task_id not in seen_injections:
            add(pair)
    for pair in ordered:
        if len(selected) >= 18:
            break
        if pair.user_task_id not in seen_users or pair.injection_task_id not in seen_injections:
            add(pair)
    for pair in ordered:
        if len(selected) >= 18:
            break
        add(pair)
    return selected


def _require_sha256(value: str, field_name: str) -> str:
    if len(value) != 64 or any(char not in _HEX64 for char in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 hex digest")
    return value


def _require_model_config_hash(value: str) -> str:
    return _require_sha256(value, "model_config_hash")


def _expected_plan(
    pairs: Sequence[AgentDojoPair],
    phase: Literal["development", "formal"],
    model_config_hash: str,
) -> list[AgentDojoRunSpec]:
    normalized = [_coerce_pair(pair) for pair in pairs]
    expected_pair_count = 2 if phase == "development" else 16
    if len(normalized) != expected_pair_count:
        raise ValueError(f"{phase} AgentDojo plan requires exactly {expected_pair_count} pairs")
    if any(not pair.runnable for pair in normalized):
        raise ValueError("run plans can only use runnable AgentDojo pairs")
    if len({pair.canonical_key for pair in normalized}) != len(normalized):
        raise ValueError("duplicate AgentDojo pair in run-plan input")
    model_config_hash = _require_model_config_hash(model_config_hash)
    rows: list[AgentDojoRunSpec] = []
    for pair in normalized:
        for attack in _ATTACKS:
            for defense in _DEFENSES:
                rows.append(
                    AgentDojoRunSpec(
                        phase=phase,
                        user_task_id=pair.user_task_id,
                        injection_task_id=pair.injection_task_id,
                        attack=attack,
                        defense=defense,
                        model_config_hash=model_config_hash,
                    )
                )
    users = sorted({pair.user_task_id for pair in normalized})
    for user_task_id in users:
        for defense in _DEFENSES:
            rows.append(
                AgentDojoRunSpec(
                    phase=phase,
                    user_task_id=user_task_id,
                    injection_task_id=None,
                    attack="none",
                    defense=defense,
                    model_config_hash=model_config_hash,
                )
            )
    return rows



def build_matrix_plan(
    pairs: Sequence[AgentDojoPair],
    model_config_hash: str,
    *,
    phase: Literal["development", "formal"],
    suite_name: str,
    clean_user_task_ids: Sequence[str] = (),
) -> list[AgentDojoRunSpec]:
    """Build an arbitrary-size, suite-aware canonical AgentDojo matrix."""

    if suite_name not in AGENTDOJO_SUITES:
        raise ValueError(f"unsupported AgentDojo suite: {suite_name}")
    if phase not in {"development", "formal"}:
        raise ValueError(f"unsupported AgentDojo phase: {phase}")
    normalized = [_coerce_pair(pair) for pair in pairs]
    if any(pair.suite != suite_name for pair in normalized):
        raise ValueError("all matrix pairs must use the requested suite")
    if any(not pair.runnable for pair in normalized):
        raise ValueError("run plans can only use runnable AgentDojo pairs")
    if len({pair.canonical_key for pair in normalized}) != len(normalized):
        raise ValueError("duplicate AgentDojo pair in run-plan input")
    model_config_hash = _require_model_config_hash(model_config_hash)
    users = tuple(dict.fromkeys(str(user) for user in clean_user_task_ids))
    rows: list[AgentDojoRunSpec] = []
    for pair in normalized:
        for attack in CANONICAL_ATTACKS:
            for defense in DEFENSES:
                rows.append(AgentDojoRunSpec(
                    suite=suite_name, phase=phase,
                    user_task_id=pair.user_task_id,
                    injection_task_id=pair.injection_task_id,
                    attack=attack, defense=defense,
                    model_config_hash=model_config_hash,
                ))
    for user_task_id in users:
        for defense in DEFENSES:
            rows.append(AgentDojoRunSpec(
                suite=suite_name, phase=phase,
                user_task_id=user_task_id, injection_task_id=None,
                attack="none", defense=defense,
                model_config_hash=model_config_hash,
            ))
    return rows
def build_development_plan(
    pairs: Sequence[AgentDojoPair], model_config_hash: str
) -> list[AgentDojoRunSpec]:
    """Build the separate eight-cell-per-pair development plan."""

    return _expected_plan(pairs, "development", model_config_hash)


def build_formal_plan(
    pairs: Sequence[AgentDojoPair], model_config_hash: str
) -> list[AgentDojoRunSpec]:
    """Build the exact attacked-plus-clean formal plan for frozen pairs."""

    return _expected_plan(pairs, "formal", model_config_hash)


def validate_agentdojo_plan(
    rows: Sequence[AgentDojoRunSpec | Mapping[str, Any]],
    pairs: Sequence[AgentDojoPair],
    model_config_hash: str,
    phase: Literal["development", "formal"] = "formal",
    *,
    manifest: AgentDojoFrozenManifest | None = None,
    served_model_name: str,
    model_checkpoint_path: str,
    model_checkpoint_sha256: str,
) -> None:
    """Reject duplicate, missing, or added cells in a native plan.

    Validation compares the complete cell key, not just Cartesian dimensions;
    therefore an injection ID paired with the wrong user task is an added cell
    and the original paired cell is simultaneously reported as missing.
    """

    # Runtime identity values are required even when a manifest is supplied.
    # The manifest is the frozen expected identity; these explicit arguments
    # are the observed victim identity and therefore cannot self-compare.
    validate_agentdojo_model_binding(
        manifest,
        model_config_hash,
        served_model_name,
        model_checkpoint_path,
        model_checkpoint_sha256,
    )
    expected_model_config_hash = model_config_hash
    expected = _expected_plan(pairs, phase, expected_model_config_hash)
    actual = [AgentDojoRunSpec.model_validate(row) for row in rows]
    if any(row.model_config_hash != expected_model_config_hash for row in actual):
        raise ValueError("AgentDojo run plan model_config_hash mismatch")
    actual_keys = [
        (row.phase, row.user_task_id, row.injection_task_id, row.attack, row.defense)
        for row in actual
    ]
    if len(actual_keys) != len(set(actual_keys)):
        raise ValueError("duplicate AgentDojo run-plan cell")
    actual_run_ids = [row.run_id for row in actual]
    if len(actual_run_ids) != len(set(actual_run_ids)):
        raise ValueError("duplicate AgentDojo run_id")
    expected_keys = [
        (row.phase, row.user_task_id, row.injection_task_id, row.attack, row.defense)
        for row in expected
    ]
    expected_set = set(expected_keys)
    actual_set = set(actual_keys)
    missing = expected_set - actual_set
    if missing:
        raise ValueError(f"missing AgentDojo run-plan cell(s): {sorted(missing)!r}")
    added = actual_set - expected_set
    if added:
        raise ValueError(f"unexpected/added AgentDojo run-plan cell(s): {sorted(added)!r}")
    expected_by_key = dict(zip(expected_keys, expected, strict=True))
    for row, key in zip(actual, actual_keys, strict=True):
        if row.run_id != expected_by_key[key].run_id:
            raise ValueError(f"non-canonical AgentDojo run_id for cell: {key!r}")
    if len(actual) != len(expected):
        raise ValueError("AgentDojo run plan has unexpected/added cells")


def plan_jsonl(rows: Sequence[AgentDojoRunSpec]) -> str:
    """Serialize a plan deterministically for a frozen JSONL artifact."""

    return "\n".join(row.model_dump_json() for row in rows) + ("\n" if rows else "")


__all__ = [
    "AgentDojoFrozenManifest",
    "AGENTDOJO_SUITES",
    "CANONICAL_ATTACKS",
    "DEFENSES",
    "AgentDojoPair",
    "AgentDojoResultRecord",
    "AgentDojoRunSpec",
    "build_matrix_plan",
    "build_development_plan",
    "build_formal_plan",
    "canonical_pair",
    "plan_jsonl",
    "validate_agentdojo_model_binding",
    "select_agentdojo_pairs",
    "validate_agentdojo_plan",
    "TRANSFER_DEFENSES",
    "build_transfer_plan_from_rows",
]

def build_transfer_plan_from_rows(
    baseline_rows: Sequence[AgentDojoRunSpec | Mapping[str, Any]],
) -> list[AgentDojoRunSpec]:
    """Expand an existing frozen baseline plan to the seven transfer arms."""

    normalized = [AgentDojoRunSpec.model_validate(row) for row in baseline_rows]
    expanded: list[AgentDojoRunSpec] = []
    seen: set[tuple[str, str, str | None, str, str, str]] = set()
    seen_base: set[tuple[str, str, str | None, str]] = set()
    for row in normalized:
        base_key = (row.phase, row.suite, row.user_task_id, row.injection_task_id, row.attack)
        if base_key in seen_base:
            continue
        seen_base.add(base_key)
        for defense in TRANSFER_DEFENSES:
            cell = AgentDojoRunSpec(
                suite=row.suite,
                phase=row.phase,
                user_task_id=row.user_task_id,
                injection_task_id=row.injection_task_id,
                attack=row.attack,
                defense=defense,
                model_config_hash=row.model_config_hash,
            )
            key = (cell.phase, cell.suite, cell.user_task_id, cell.injection_task_id, cell.attack, defense)
            if key in seen:
                raise ValueError(f"duplicate transfer plan cell: {key!r}")
            seen.add(key)
            expanded.append(cell)
    return expanded
