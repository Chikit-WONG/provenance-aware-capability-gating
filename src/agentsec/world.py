"""In-memory mock office world and append-only structured audit log."""

from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from threading import RLock
from typing import Any, Iterable

from .schemas import (
    AuditEvent,
    CalendarEvent,
    Decision,
    EmailRecord,
    EventKind,
    FileRecord,
    ProvenanceLabel,
    SentEmail,
    ToolName,
    WorldState,
)


class AuditLog:
    """A small append-only event store with monotonic IDs and defensive reads."""

    def __init__(self, events: Iterable[AuditEvent] = ()) -> None:
        copied = [event.model_copy(deep=True) for event in events]
        for expected, event in enumerate(copied, start=1):
            if event.sequence != expected:
                raise ValueError("preloaded audit events must have contiguous sequences starting at 1")
            if event.event_id != f"evt-{expected:06d}":
                raise ValueError("preloaded audit event IDs must match their sequence")
        self._events = copied
        self._lock = RLock()

    def append(
        self,
        event_kind: EventKind | str,
        actor: str,
        *,
        tool: ToolName | str | None = None,
        arguments: dict[str, Any] | None = None,
        resource_ids: Iterable[str] = (),
        provenance: ProvenanceLabel | None = None,
        decision: Decision | str | None = None,
        reason: str = "",
        success: bool | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEvent:
        with self._lock:
            sequence = len(self._events) + 1
            event = AuditEvent(
                sequence=sequence,
                event_id=f"evt-{sequence:06d}",
                event_kind=event_kind,
                actor=actor,
                tool=tool,
                arguments=deepcopy(arguments or {}),
                resource_ids=tuple(resource_ids),
                provenance=provenance.model_copy(deep=True) if provenance else None,
                decision=decision,
                reason=reason,
                success=success,
                timestamp=timestamp or datetime.now(timezone.utc),
            )
            self._events.append(event)
            return event.model_copy(deep=True)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(event.model_copy(deep=True) for event in self._events)

    def get(self, event_id: str) -> AuditEvent | None:
        with self._lock:
            for event in self._events:
                if event.event_id == event_id:
                    return event.model_copy(deep=True)
        return None

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


def _parse_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        # Scenario timestamps are registered in Asia/Shanghai (+08:00); naive
        # values follow that convention, matching policy.py and evaluator.py.
        parsed = parsed.replace(tzinfo=timezone(timedelta(hours=8)))
    return parsed


class MockWorld:
    """Mutable runtime facade over defensively copied, serialisable snapshots.

    ``fresh_clone`` always returns the initial snapshot, not the current state.
    This is the operation runners should use between retries and benchmark arms.
    """

    def __init__(self, initial_state: WorldState) -> None:
        self._initial_state = initial_state.model_copy(deep=True)
        self._load(initial_state)
        self._lock = RLock()

    def _load(self, state: WorldState) -> None:
        copied = state.model_copy(deep=True)
        self._emails: dict[str, EmailRecord] = dict(copied.emails)
        self._files: dict[str, FileRecord] = dict(copied.files)
        self._calendar_events: dict[str, CalendarEvent] = dict(copied.calendar_events)
        self._outbox: list[SentEmail] = list(copied.outbox)

    def snapshot(self) -> WorldState:
        with self._lock:
            return WorldState(
                emails=deepcopy(self._emails),
                files=deepcopy(self._files),
                calendar_events=deepcopy(self._calendar_events),
                outbox=tuple(deepcopy(self._outbox)),
            )

    def fresh_clone(self) -> "MockWorld":
        return MockWorld(self._initial_state.model_copy(deep=True))

    def current_clone(self) -> "MockWorld":
        return MockWorld(self.snapshot())

    def search_emails(self, query: str) -> tuple[EmailRecord, ...]:
        needle = query.casefold().strip()
        with self._lock:
            matches = [
                email
                for email in self._emails.values()
                if not needle
                or needle in email.subject.casefold()
                or needle in email.sender.casefold()
                or needle in email.body.casefold()
            ]
            return tuple(email.model_copy(deep=True) for email in matches)

    def read_email(self, email_id: str) -> EmailRecord:
        with self._lock:
            try:
                return self._emails[email_id].model_copy(deep=True)
            except KeyError as error:
                raise KeyError(f"unknown email_id: {email_id}") from error

    def read_file(self, file_id: str) -> FileRecord:
        with self._lock:
            try:
                return self._files[file_id].model_copy(deep=True)
            except KeyError as error:
                raise KeyError(f"unknown file_id: {file_id}") from error

    def search_calendar(self, date_value: str) -> tuple[CalendarEvent, ...]:
        target = date.fromisoformat(date_value)
        with self._lock:
            matches = [
                event
                for event in self._calendar_events.values()
                if _parse_datetime(event.start).date() == target
            ]
            return tuple(event.model_copy(deep=True) for event in matches)

    def send_email(self, to: str, subject: str, body: str, cc: tuple[str, ...] = ()) -> SentEmail:
        if not to.strip():
            raise ValueError("to cannot be blank")
        with self._lock:
            existing = {message.message_id for message in self._outbox}
            index = len(self._outbox) + 1
            message_id = f"sent-{index:04d}"
            while message_id in existing:
                index += 1
                message_id = f"sent-{index:04d}"
            sent = SentEmail(
                message_id=message_id,
                to=to,
                subject=subject,
                body=body,
                cc=tuple(cc),
            )
            self._outbox.append(sent)
            return sent.model_copy(deep=True)

    def create_calendar_event(
        self,
        title: str,
        start: str,
        end: str,
        participants: tuple[str, ...] = (),
        location: str = "",
    ) -> CalendarEvent:
        start_time = _parse_datetime(start)
        end_time = _parse_datetime(end)
        if end_time <= start_time:
            raise ValueError("calendar event end must be after start")
        if not title.strip():
            raise ValueError("calendar event title cannot be blank")
        with self._lock:
            index = len(self._calendar_events) + 1
            event_id = f"cal-created-{index:04d}"
            while event_id in self._calendar_events:
                index += 1
                event_id = f"cal-created-{index:04d}"
            event = CalendarEvent(
                event_id=event_id,
                title=title,
                start=start,
                end=end,
                participants=tuple(participants),
                location=location,
            )
            self._calendar_events[event_id] = event
            return event.model_copy(deep=True)
