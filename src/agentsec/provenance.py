"""Immutable provenance labels and deliberately exact protected-value tracking."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict

from .schemas import Authority, ProtectedValue, ProvenanceLabel, Sensitivity


SENSITIVITY_RANK: dict[Sensitivity, int] = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.SECRET: 2,
}


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
