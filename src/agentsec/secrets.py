"""Opaque secret references and purpose-bound redemption.

The broker is deliberately separate from capability and provenance policy.
Sensitive literals are replaced before data enters an LLM context.  A model may
carry an opaque reference, but only trusted executor code can redeem it for an
explicitly registered consumer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from .schemas import ProtectedValue, Sensitivity


SECRET_REFERENCE_PREFIX = "secret://"
REDACTED_SECRET = "[REDACTED_SECRET]"


class SecretBrokerError(RuntimeError):
    """Base class for fail-closed broker errors."""


class SecretAccessDenied(SecretBrokerError):
    """A secret reference could not be redeemed for the requested consumer."""


@dataclass(frozen=True)
class SecretRegistration:
    """Metadata for one secret; the literal is intentionally not exposed."""

    secret_id: str
    reference: str
    source_resource_id: str
    allowed_consumers: tuple[str, ...]
    max_uses: int
    expires_at: datetime | None


@dataclass
class _StoredSecret:
    registration: SecretRegistration
    value: str
    uses: int = 0


class SecretBroker:
    """Keep secret plaintext out of model-visible values.

    References are identifiers, not bearer credentials.  Possessing or guessing
    ``secret://deploy-token`` is insufficient: redemption also requires a
    matching trusted consumer, an unexpired grant, and remaining uses.
    """

    def __init__(self) -> None:
        self._by_reference: dict[str, _StoredSecret] = {}
        self._reference_by_value: dict[str, str] = {}
        self._lock = RLock()

    @classmethod
    def from_protected_values(
        cls,
        values: Iterable[ProtectedValue],
        *,
        minimum_sensitivity: Sensitivity = Sensitivity.SECRET,
    ) -> "SecretBroker":
        """Register scenario values at or above ``minimum_sensitivity``.

        Scenario-derived registrations do not grant redemption.  Deployments
        must explicitly register trusted consumers for secrets that a tool is
        allowed to use.
        """

        ranks = {
            Sensitivity.PUBLIC: 0,
            Sensitivity.INTERNAL: 1,
            Sensitivity.SECRET: 2,
        }
        broker = cls()
        for protected in values:
            if ranks[protected.sensitivity] < ranks[minimum_sensitivity]:
                continue
            broker.register(
                protected.protected_id,
                protected.value,
                source_resource_id=protected.source_resource_id,
            )
        return broker

    def register(
        self,
        secret_id: str,
        value: str,
        *,
        source_resource_id: str = "",
        allowed_consumers: Iterable[str] = (),
        max_uses: int = 1,
        expires_at: datetime | None = None,
    ) -> str:
        """Register a literal and return its stable opaque reference."""

        normalized_id = secret_id.strip()
        if not normalized_id:
            raise ValueError("secret_id cannot be blank")
        if not value:
            raise ValueError("secret value cannot be empty")
        if max_uses < 1:
            raise ValueError("max_uses must be positive")
        consumers = tuple(dict.fromkeys(item.strip() for item in allowed_consumers))
        if any(not item for item in consumers):
            raise ValueError("allowed consumer names cannot be blank")
        if expires_at is not None and expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")

        reference = f"{SECRET_REFERENCE_PREFIX}{quote(normalized_id, safe='-._~')}"
        registration = SecretRegistration(
            secret_id=normalized_id,
            reference=reference,
            source_resource_id=source_resource_id,
            allowed_consumers=consumers,
            max_uses=max_uses,
            expires_at=expires_at,
        )
        with self._lock:
            if reference in self._by_reference:
                raise ValueError(f"duplicate secret_id: {normalized_id}")
            if value in self._reference_by_value:
                raise ValueError("the same secret value cannot be registered twice")
            self._by_reference[reference] = _StoredSecret(registration, value)
            self._reference_by_value[value] = reference
        return reference

    @property
    def registrations(self) -> tuple[SecretRegistration, ...]:
        """Return metadata only; plaintext never leaves through this API."""

        with self._lock:
            return tuple(
                item.registration
                for _, item in sorted(self._by_reference.items())
            )

    def tokenize_for_model(self, value: Any) -> Any:
        """Recursively replace registered literals with opaque references."""

        return self._transform(value, self._tokenize_text)

    def redact_for_display(self, value: Any) -> Any:
        """Remove both plaintext and references from user-visible/persisted data."""

        return self._transform(value, self._redact_text)

    def detected_secret_ids(
        self,
        value: Any,
        *,
        include_references: bool = True,
    ) -> tuple[str, ...]:
        """Return IDs of plaintext secrets or references present in ``value``."""

        matches: set[str] = set()
        for text in self._strings(value):
            with self._lock:
                items = tuple(self._by_reference.items())
            for reference, stored in items:
                if stored.value in text or (include_references and reference in text):
                    matches.add(stored.registration.secret_id)
        return tuple(sorted(matches))

    def redeem(
        self,
        reference: str,
        *,
        consumer: str,
        now: datetime | None = None,
    ) -> str:
        """Redeem one reference for a trusted, purpose-bound consumer."""

        normalized_consumer = consumer.strip()
        if not normalized_consumer:
            raise SecretAccessDenied("secret consumer cannot be blank")
        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        with self._lock:
            stored = self._by_reference.get(reference)
            if stored is None:
                raise SecretAccessDenied("unknown secret reference")
            registration = stored.registration
            if normalized_consumer not in registration.allowed_consumers:
                raise SecretAccessDenied(
                    f"consumer {normalized_consumer!r} is not authorized for "
                    f"{registration.secret_id!r}"
                )
            if registration.expires_at is not None and current_time >= registration.expires_at:
                raise SecretAccessDenied(f"secret {registration.secret_id!r} has expired")
            if stored.uses >= registration.max_uses:
                raise SecretAccessDenied(
                    f"secret {registration.secret_id!r} has no remaining uses"
                )
            stored.uses += 1
            return stored.value

    def _tokenize_text(self, text: str) -> str:
        with self._lock:
            replacements = sorted(
                self._reference_by_value.items(),
                key=lambda item: len(item[0]),
                reverse=True,
            )
        for literal, reference in replacements:
            text = text.replace(literal, reference)
        return text

    def _redact_text(self, text: str) -> str:
        tokenized = self._tokenize_text(text)
        with self._lock:
            references = tuple(
                sorted(self._by_reference, key=len, reverse=True)
            )
        for reference in references:
            tokenized = tokenized.replace(reference, REDACTED_SECRET)
        return tokenized

    @classmethod
    def _transform(cls, value: Any, transform: Any) -> Any:
        if isinstance(value, str):
            return transform(value)
        if isinstance(value, Mapping):
            return {
                key: cls._transform(item, transform)
                for key, item in value.items()
            }
        if isinstance(value, tuple):
            return tuple(cls._transform(item, transform) for item in value)
        if isinstance(value, list):
            return [cls._transform(item, transform) for item in value]
        if isinstance(value, set):
            return {cls._transform(item, transform) for item in value}
        return value

    @classmethod
    def _strings(cls, value: Any) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, Mapping):
            for item in value.values():
                yield from cls._strings(item)
        elif isinstance(value, (tuple, list, set)):
            for item in value:
                yield from cls._strings(item)


__all__ = [
    "REDACTED_SECRET",
    "SECRET_REFERENCE_PREFIX",
    "SecretAccessDenied",
    "SecretBroker",
    "SecretBrokerError",
    "SecretRegistration",
]
