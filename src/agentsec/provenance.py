"""Immutable provenance labels and deliberately exact protected-value tracking.

Vocabulary note: the module now also carries the project's trust lattice
(:class:`TrustLevel`) and a conservative-merge provenance tag
(:class:`ProvenanceTag`), modelled on argument-level provenance contracts
(PACT, arXiv:2605.11039).  Within that framing the :class:`ExactTaintTracker`
below is the *credential-egress* enforcement: it blocks registered protected
values from leaving through CONTENT-role sink fields.  Full data-flow
provenance inference (deriving tags for every intermediate value) is
deliberately out of scope and documented as future work.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict

from .schemas import Authority, ProtectedValue, ProvenanceLabel, Sensitivity, TrustLevel


SENSITIVITY_RANK: dict[Sensitivity, int] = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.SECRET: 2,
}

TRUST_RANK: dict[TrustLevel, int] = {
    TrustLevel.EXTERNAL: 0,
    TrustLevel.TOOL_OUTPUT: 1,
    TrustLevel.USER: 2,
    TrustLevel.TRUSTED: 3,
}


def lowest_trust(values: Iterable[TrustLevel]) -> TrustLevel:
    """Conservative (fail-low) join on the trust lattice."""

    result = TrustLevel.TRUSTED
    for value in values:
        if TRUST_RANK[value] < TRUST_RANK[result]:
            result = value
    return result


def trust_for_authority(authority: Authority) -> TrustLevel:
    """Map the audit-trail authority vocabulary onto the trust lattice.

    DERIVED values are conservatively treated as TOOL_OUTPUT: a derived
    context may mix user and external content, so it must not inherit USER
    trust by default.
    """

    return {
        Authority.TRUSTED: TrustLevel.TRUSTED,
        Authority.UNTRUSTED: TrustLevel.EXTERNAL,
        Authority.DERIVED: TrustLevel.TOOL_OUTPUT,
    }[authority]


class ProvenanceTag(BaseModel):
    """Provenance of one runtime value: contributing origins, current trust,
    and unresolved obligations.  Merged conservatively (see :func:`merge_tags`):
    ordinary dataflow never increases trust and never erases origins.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    origins: tuple[str, ...] = ()
    trust: TrustLevel = TrustLevel.EXTERNAL
    obligations: tuple[str, ...] = ()


def merge_tags(*tags: ProvenanceTag) -> ProvenanceTag:
    """Conservative provenance merge: union origins/obligations, fail-low trust."""

    return ProvenanceTag(
        origins=tuple(dict.fromkeys(origin for tag in tags for origin in tag.origins)),
        trust=lowest_trust(tag.trust for tag in tags),
        obligations=tuple(
            dict.fromkeys(ob for tag in tags for ob in tag.obligations)
        ),
    )


def tag_from_label(
    label: ProvenanceLabel,
    *,
    origin: str | None = None,
) -> ProvenanceTag:
    """Translate an audit label into the runtime contract vocabulary."""

    origins = tuple(
        dict.fromkeys(
            item
            for item in (
                *label.source_event_ids,
                *label.parent_event_ids,
                *((origin,) if origin else ()),
            )
            if item
        )
    )
    return ProvenanceTag(
        origins=origins,
        trust=trust_for_authority(label.authority),
    )


class RuntimeProvenance:
    """Conservative value provenance used by the experimental PACT-L2 arm.

    The resolver deliberately implements a small, auditable subset of PACT's
    deployment pipeline.  It recognizes values present in the trusted user
    request, exact values and substrings observed in tool outputs, and explicit
    derived values.  Unknown authority-bearing values fail low as EXTERNAL.

    This is not semantic taint inference.  Callers must use :meth:`derive` when
    an application transformation creates a new value from known parents.
    """

    _AUTHORITY_ROLES = frozenset({"target", "command", "credential", "control"})

    def __init__(self) -> None:
        self._user_values: list[tuple[Any, ProvenanceTag]] = []
        self._observed_values: list[tuple[Any, ProvenanceTag]] = []
        self._derived: dict[str, ProvenanceTag] = {}

    def observe_user_input(
        self,
        value: Any,
        *,
        origin: str = "user-request",
    ) -> None:
        tag = ProvenanceTag(origins=(origin,), trust=TrustLevel.USER)
        self._user_values.extend((item, tag) for item in self._leaf_values(value))

    def observe_tool_output(
        self,
        value: Any,
        label: ProvenanceLabel,
        *,
        origin: str,
    ) -> None:
        tag = tag_from_label(label, origin=origin)
        self._observed_values.extend((item, tag) for item in self._leaf_values(value))

    def observe_derived(
        self,
        value: Any,
        *parents: Any,
        origin: str = "derived",
    ) -> ProvenanceTag:
        """Register a transformation while retaining all parent origins."""

        parent_tags = tuple(self.resolve(parent, role="content") for parent in parents)
        tag = (
            merge_tags(*parent_tags)
            if parent_tags
            else ProvenanceTag(origins=(origin,), trust=TrustLevel.EXTERNAL)
        )
        tag = ProvenanceTag(
            origins=tuple(dict.fromkeys((*tag.origins, origin))),
            trust=tag.trust,
            obligations=tag.obligations,
        )
        self._derived[self._key(value)] = tag
        return tag

    def resolve(self, value: Any, *, role: Any = "content") -> ProvenanceTag:
        """Resolve one argument value, failing low when its origin is unknown."""

        role_text = str(getattr(role, "value", role))
        if self._is_empty(value):
            return ProvenanceTag(origins=("empty-value",), trust=TrustLevel.TRUSTED)

        leaves = self._leaf_values(value)
        if not leaves:
            return ProvenanceTag(origins=("unknown",), trust=TrustLevel.EXTERNAL)
        tags = tuple(self._resolve_leaf(item, role_text) for item in leaves)
        return merge_tags(*tags)

    def _resolve_leaf(self, value: Any, role: str) -> ProvenanceTag:
        if role in self._AUTHORITY_ROLES:
            user_matches = self._matching_tags(value, self._user_values)
            if user_matches:
                # An explicit user value authorizes the same authority binding
                # even if an attacker repeats that value in external content.
                return merge_tags(*user_matches)

        matches = self._matching_tags(value, self._observed_values)
        derived = self._derived.get(self._key(value))
        if derived is not None:
            matches = (*matches, derived)
        if matches:
            return merge_tags(*matches)

        user_matches = self._matching_tags(value, self._user_values)
        if user_matches:
            return merge_tags(*user_matches)
        return ProvenanceTag(origins=("unknown",), trust=TrustLevel.EXTERNAL)

    @classmethod
    def _matching_tags(
        cls,
        value: Any,
        candidates: Iterable[tuple[Any, ProvenanceTag]],
    ) -> tuple[ProvenanceTag, ...]:
        matches: list[ProvenanceTag] = []
        for candidate, tag in candidates:
            if cls._matches(value, candidate):
                matches.append(tag)
        return tuple(matches)

    @staticmethod
    def _matches(value: Any, candidate: Any) -> bool:
        if value == candidate:
            return True
        if not isinstance(value, str) or not isinstance(candidate, str):
            return False
        needle = value.strip().casefold()
        haystack = candidate.casefold()
        if len(needle) >= 3 and needle in haystack:
            return True
        if "@" in needle:
            local_part = needle.split("@", 1)[0]
            return bool(
                len(local_part) >= 3
                and re.search(rf"\b{re.escape(local_part)}\b", haystack)
            )
        return False

    @classmethod
    def _leaf_values(cls, value: Any) -> tuple[Any, ...]:
        leaves: list[Any] = []

        def collect(item: Any) -> None:
            if isinstance(item, Mapping):
                for nested in item.values():
                    collect(nested)
            elif isinstance(item, Sequence) and not isinstance(
                item, (str, bytes, bytearray)
            ):
                for nested in item:
                    collect(nested)
            elif isinstance(item, (str, int, float, bool)):
                leaves.append(item)

        collect(value)
        return tuple(leaves)

    @staticmethod
    def _is_empty(value: Any) -> bool:
        return value is None or value == "" or (
            isinstance(value, (Mapping, Sequence))
            and not isinstance(value, (str, bytes, bytearray))
            and len(value) == 0
        )

    @staticmethod
    def _key(value: Any) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return repr(value)


class DetectedTaint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protected_id: str
    value: str
    sensitivity: Sensitivity
    source_resource_id: str
    source_event_ids: tuple[str, ...] = ()


def highest_sensitivity(values: Iterable[Sensitivity]) -> Sensitivity:
    result = Sensitivity.PUBLIC
    for value in values:
        if SENSITIVITY_RANK[value] > SENSITIVITY_RANK[result]:
            result = value
    return result


def join_provenance(
    labels: Iterable[ProvenanceLabel], *, parent_event_ids: Iterable[str] = ()
) -> ProvenanceLabel:
    """Conservatively label a derived context while retaining source IDs."""

    labels = tuple(labels)
    source_ids: list[str] = []
    parents: list[str] = list(parent_event_ids)
    for label in labels:
        source_ids.extend(label.source_event_ids)
        parents.extend(label.parent_event_ids)
    return ProvenanceLabel(
        authority=Authority.DERIVED,
        sensitivity=highest_sensitivity(label.sensitivity for label in labels),
        source_event_ids=tuple(dict.fromkeys(source_ids)),
        parent_event_ids=tuple(dict.fromkeys(parents)),
    )


class ExactTaintTracker:
    """Track verbatim occurrences of registered synthetic protected values.

    This intentionally does not decode, normalise, fuzzy-match, or infer semantic
    equivalents.  Those transformations are outside the project's formal claim.
    """

    def __init__(self, protected_values: Iterable[ProtectedValue] = ()) -> None:
        values = tuple(value.model_copy(deep=True) for value in protected_values)
        identifiers = [value.protected_id for value in values]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("protected_id values must be unique")
        self._protected_values = values
        self._source_events: dict[str, list[str]] = {
            value.protected_id: [] for value in values
        }

    @property
    def protected_values(self) -> tuple[ProtectedValue, ...]:
        return tuple(value.model_copy(deep=True) for value in self._protected_values)

    def observe_read(self, event_id: str, resource_ids: Iterable[str]) -> None:
        resource_ids = set(resource_ids)
        for value in self._protected_values:
            if value.source_resource_id in resource_ids:
                events = self._source_events[value.protected_id]
                if event_id not in events:
                    events.append(event_id)

    def scan(self, value: Any) -> tuple[DetectedTaint, ...]:
        """Recursively scan string values (not mapping keys) for exact literals."""

        strings: list[str] = []
        self._collect_strings(value, strings)
        detected: list[DetectedTaint] = []
        for protected in self._protected_values:
            if any(protected.value in text for text in strings):
                detected.append(
                    DetectedTaint(
                        protected_id=protected.protected_id,
                        value=protected.value,
                        sensitivity=protected.sensitivity,
                        source_resource_id=protected.source_resource_id,
                        source_event_ids=tuple(self._source_events[protected.protected_id]),
                    )
                )
        return tuple(detected)

    def scan_fields(
        self, arguments: Mapping[str, Any], fields: Iterable[str]
    ) -> tuple[DetectedTaint, ...]:
        selected = {field: arguments[field] for field in fields if field in arguments}
        return self.scan(selected)

    def provenance_for(
        self, taints: Iterable[DetectedTaint], *, parent_event_ids: Iterable[str] = ()
    ) -> ProvenanceLabel | None:
        taints = tuple(taints)
        if not taints:
            return None
        source_ids = tuple(
            dict.fromkeys(event_id for taint in taints for event_id in taint.source_event_ids)
        )
        return ProvenanceLabel(
            authority=Authority.DERIVED,
            sensitivity=highest_sensitivity(taint.sensitivity for taint in taints),
            source_event_ids=source_ids,
            parent_event_ids=tuple(dict.fromkeys(parent_event_ids)),
        )

    @classmethod
    def _collect_strings(cls, value: Any, output: list[str]) -> None:
        if isinstance(value, str):
            output.append(value)
        elif isinstance(value, Mapping):
            for nested in value.values():
                cls._collect_strings(nested, output)
        elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            for nested in value:
                cls._collect_strings(nested, output)
