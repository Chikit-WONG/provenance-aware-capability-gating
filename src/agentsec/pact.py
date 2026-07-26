"""Minimal deterministic PACT (provenance-aware capability control) core.

This module is deliberately smaller than the model-driven benchmark harness.
It makes the central distinction auditable: a capability allow-list answers
whether a value is permitted, while PACT also checks whether that value may be
bound to the requested parameter role.  Only explicitly registered
transformations can preserve trusted provenance into high-impact roles.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator


HIGH_TRUST_ROLES = frozenset({"recipient", "target", "control"})


def _value_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class PACTAuthority(str, Enum):
    USER = "user"
    EXTERNAL = "external"
    REGISTERED_TRANSFORM = "registered_transform"


class PACTProvenance(BaseModel):
    """Immutable source label carried with one tool argument."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authority: PACTAuthority
    source_id: str
    source_value_sha256: str
    value_sha256: str
    transform_chain: tuple[str, ...] = ()
    source_authority: PACTAuthority | None = None

    @field_validator("source_id")
    @classmethod
    def source_id_nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("source_id cannot be empty")
        return value

    @classmethod
    def user(cls, value: Any, *, source_id: str = "user_request") -> "PACTProvenance":
        digest = _value_hash(value)
        return cls(
            authority=PACTAuthority.USER,
            source_id=source_id,
            source_value_sha256=digest,
            value_sha256=digest,
            source_authority=PACTAuthority.USER,
        )

    @classmethod
    def external(cls, value: Any, *, source_id: str) -> "PACTProvenance":
        return cls(
            authority=PACTAuthority.EXTERNAL,
            source_id=source_id,
            source_value_sha256=_value_hash(value),
            value_sha256=_value_hash(value),
            source_authority=PACTAuthority.EXTERNAL,
        )

    @classmethod
    def registered_transform(
        cls,
        *,
        source_value: Any,
        output_value: Any,
        transform_name: str,
        source_authority: PACTAuthority,
        source_id: str = "registered_transform",
    ) -> "PACTProvenance":
        if source_authority not in {PACTAuthority.USER, PACTAuthority.REGISTERED_TRANSFORM}:
            raise ValueError("registered transformations must start from trusted provenance")
        return cls(
            authority=PACTAuthority.REGISTERED_TRANSFORM,
            source_id=source_id,
            source_value_sha256=_value_hash(source_value),
            value_sha256=_value_hash(output_value),
            transform_chain=(transform_name,),
            source_authority=source_authority,
        )

    def digest(self) -> str:
        return hashlib.sha256(
            self.model_dump_json(exclude_none=True, by_alias=True).encode("utf-8")
        ).hexdigest()


class PACTArgument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    role: str
    value: Any
    provenance: PACTProvenance


class PACTCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    arguments: dict[str, PACTArgument] = Field(default_factory=dict)


class CapabilityManifest(BaseModel):
    """Ordinary value allow-list; it intentionally has no source semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    allowed_values: dict[str, tuple[Any, ...]] = Field(default_factory=dict)


class _TransformationKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    source_value_sha256: str
    output_value_sha256: str
    source_authority: PACTAuthority


class TransformationRegistry:
    """Exact-match registry for declared value transformations."""

    def __init__(self) -> None:
        self._entries: set[_TransformationKey] = set()

    def register(
        self,
        transform_name: str,
        source_value: Any,
        output_value: Any,
        *,
        source_authority: PACTAuthority,
    ) -> None:
        if source_authority not in {PACTAuthority.USER, PACTAuthority.REGISTERED_TRANSFORM}:
            raise ValueError("only trusted provenance may be registered for a transform")
        self._entries.add(
            _TransformationKey(
                name=transform_name,
                source_value_sha256=_value_hash(source_value),
                output_value_sha256=_value_hash(output_value),
                source_authority=source_authority,
            )
        )

    def verify(self, provenance: PACTProvenance, value: Any) -> bool:
        if provenance.authority is not PACTAuthority.REGISTERED_TRANSFORM:
            return False
        if not provenance.transform_chain or provenance.value_sha256 != _value_hash(value):
            return False
        return _TransformationKey(
            name=provenance.transform_chain[-1],
            source_value_sha256=provenance.source_value_sha256,
            output_value_sha256=provenance.value_sha256,
            source_authority=provenance.source_authority or PACTAuthority.EXTERNAL,
        ) in self._entries


class PACTResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    tool: str
    arguments: dict[str, dict[str, Any]]
    capability_allowed: bool
    pact_allowed: bool
    executed: bool
    side_effect_count: int = Field(ge=0)
    transformation_verified: bool = False
    reason: str
    provenance_digests: dict[str, str]
    decision_log_sha256: str


class PACTGateway:
    """Compare ordinary capability gating with role-aware PACT decisions."""

    def __init__(self, manifest: CapabilityManifest, registry: TransformationRegistry) -> None:
        self.manifest = manifest
        self.registry = registry
        self.side_effects: list[dict[str, Any]] = []

    def _capability_check(self, call: PACTCall) -> tuple[bool, str]:
        if call.tool != self.manifest.tool:
            return False, f"tool {call.tool!r} is not granted"
        for argument in call.arguments.values():
            # The semantic role is the policy key.  ``name`` is an untrusted
            # caller-facing label and must never select a capability entry.
            allowed = self.manifest.allowed_values.get(argument.role)
            if allowed is not None and argument.value not in allowed:
                return False, f"{argument.name} value is outside capability allow-list"
        return True, "capability allow-list passed"

    def capability_decision(self, call: PACTCall) -> tuple[bool, str]:
        """Return the ordinary value-only capability decision for ``call``."""

        return self._capability_check(call)

    @staticmethod
    def _provenance_is_consistent(provenance: PACTProvenance, value: Any) -> bool:
        """Validate the immutable label/hash relation before applying policy.

        The provenance tracker is part of the trusted computing base: callers
        cannot upgrade a value by constructing a contradictory label.  User
        and external claims carry a hash of the value itself; a registered
        transform carries an output hash and is checked against the registry.
        """

        value_digest = _value_hash(value)
        if provenance.authority is PACTAuthority.USER:
            return (
                provenance.source_authority is PACTAuthority.USER
                and provenance.source_value_sha256 == value_digest
                and provenance.value_sha256 == value_digest
            )
        if provenance.authority is PACTAuthority.EXTERNAL:
            return (
                provenance.source_authority is PACTAuthority.EXTERNAL
                and provenance.source_value_sha256 == value_digest
                and provenance.value_sha256 == value_digest
            )
        if provenance.authority is PACTAuthority.REGISTERED_TRANSFORM:
            return provenance.value_sha256 == value_digest
        return False

    def _pact_check(self, call: PACTCall) -> tuple[bool, bool, str]:
        transformation_verified = False
        for argument in call.arguments.values():
            provenance = argument.provenance
            if not self._provenance_is_consistent(provenance, argument.value):
                return (
                    False,
                    transformation_verified,
                    f"provenance integrity for argument {argument.name!r} is invalid",
                )
            if argument.role in HIGH_TRUST_ROLES:
                if provenance.authority is PACTAuthority.USER:
                    continue
                if self.registry.verify(provenance, argument.value) and provenance.source_authority is PACTAuthority.USER:
                    transformation_verified = True
                    continue
                return (
                    False,
                    transformation_verified,
                    f"authority provenance for role {argument.role!r} is not trusted",
                )
            # External values are intentionally allowed at low-risk content roles.
        return True, transformation_verified, "PACT role and provenance checks passed"

    def pact_decision(self, call: PACTCall) -> tuple[bool, bool, str]:
        """Return the role/provenance decision and transform status for ``call``."""

        return self._pact_check(call)

    def execute(self, call: PACTCall, *, case_id: str) -> PACTResult:
        capability_allowed, capability_reason = self.capability_decision(call)
        pact_allowed, transformation_verified, pact_reason = self.pact_decision(call)
        allowed = capability_allowed and pact_allowed
        executed = bool(allowed)
        if executed:
            self.side_effects.append({"case_id": case_id, "tool": call.tool})
        reason = "{}; {}".format(capability_reason, pact_reason)
        arguments = {
            name: argument.model_dump(mode="json")
            for name, argument in call.arguments.items()
        }
        provenance_digests = {
            name: argument.provenance.digest() for name, argument in call.arguments.items()
        }
        payload = {
            "case_id": case_id,
            "tool": call.tool,
            "arguments": arguments,
            "capability_allowed": capability_allowed,
            "pact_allowed": pact_allowed,
            "executed": executed,
            "side_effect_count": int(executed),
            "transformation_verified": transformation_verified,
            "reason": reason,
            "provenance_digests": provenance_digests,
        }
        decision_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return PACTResult(**payload, decision_log_sha256=decision_hash)


__all__ = [
    "CapabilityManifest",
    "HIGH_TRUST_ROLES",
    "PACTArgument",
    "PACTAuthority",
    "PACTCall",
    "PACTGateway",
    "PACTProvenance",
    "PACTResult",
    "TransformationRegistry",
]
