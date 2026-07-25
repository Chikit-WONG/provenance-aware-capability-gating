"""Conservative capability/provenance gate for native AgentDojo tool calls.

The native benchmark does not expose a project-specific capability manifest or
provenance API.  This adapter therefore uses an explicit, auditable policy:
high-impact argument roles must be present in the user task (capability mode),
and exact values observed in earlier tool outputs cannot flow into an external
sink (provenance mode).  It is intentionally conservative and is not claimed
to provide semantic secret detection or decoding.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


TRANSFER_DEFENSES = (
    "capability_only",
    "provenance_only",
    "prompt_capability",
    "prompt_provenance",
    "full",
)

SINK_TO_ROLE_FIELDS: dict[str, tuple[str, ...]] = {
    "send_email": ("recipients", "cc", "bcc"),
    "create_calendar_event": ("participants",),
    "add_calendar_event_participants": ("participants",),
    "share_file": ("email",),
    "send_money": ("recipient", "recipient_email", "to", "email"),
    "schedule_transaction": ("recipient", "recipient_email", "to", "email"),
    "update_scheduled_transaction": ("recipient", "recipient_email", "to", "email"),
    "add_user_to_channel": ("user", "user_email", "email"),
    "invite_user_to_slack": ("user", "user_email", "email"),
    "send_direct_message": ("recipient", "user", "user_email", "email"),
    "send_channel_message": ("channel", "channel_id"),
}

PROVENANCE_SINKS = frozenset(
    {
        "send_email",
        "create_calendar_event",
        "add_calendar_event_participants",
        "append_to_file",
        "create_file",
        "share_file",
        "send_money",
        "schedule_transaction",
        "update_scheduled_transaction",
        "update_password",
        "update_user_info",
        "add_user_to_channel",
        "invite_user_to_slack",
        "remove_user_from_slack",
        "send_direct_message",
        "send_channel_message",
        "post_webpage",
        "reserve_hotel",
        "reserve_car_rental",
        "reserve_restaurant",
    }
)

_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_ID_RE = re.compile(r"\b(?:file|email|event|cal|msg|user|channel|txn|transaction)[-_][A-Z0-9][A-Z0-9_-]{3,}\b", re.I)
_TOKEN_RE = re.compile(r"\b(?=[A-Z0-9_-]{8,}\b)(?=.*[A-Z])(?=.*\d)[A-Z0-9_-]+\b")


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        result: list[str] = []
        for item in value.values():
            result.extend(_strings(item))
        return result
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        result = []
        for item in value:
            result.extend(_strings(item))
        return result
    if value is None or isinstance(value, (bool, int, float)):
        return []
    return [str(value)]


def _message_text(message: Mapping[str, Any]) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    return " ".join(_strings(content))


def _flatten_role_values(arguments: Mapping[str, Any], fields: Sequence[str]) -> list[str]:
    values: list[str] = []
    for field in fields:
        if field in arguments:
            values.extend(item.strip() for item in _strings(arguments[field]) if item.strip())
    return values


class AgentDojoGate:
    """Stateful gate used by the native ToolsExecutor runtime proxy."""

    def __init__(self, mode: str) -> None:
        if mode not in TRANSFER_DEFENSES:
            raise ValueError(f"unsupported AgentDojo gate mode: {mode}")
        self.mode = mode
        self._user_text = ""
        self._derived_values: set[str] = set()
        self.decisions: list[dict[str, Any]] = []

    @property
    def has_capability(self) -> bool:
        return self.mode in {"capability_only", "prompt_capability", "full"}

    @property
    def has_provenance(self) -> bool:
        return self.mode in {"provenance_only", "prompt_provenance", "full"}

    def observe_messages(self, messages: Sequence[Mapping[str, Any]]) -> None:
        self._user_text = " ".join(
            _message_text(message).casefold()
            for message in messages
            if message.get("role") == "user"
        )

    def observe_tool_output(self, tool_name: str, output: Any) -> None:
        del tool_name
        for value in _strings(output):
            for candidate in (value, *_EMAIL_RE.findall(value), *_ID_RE.findall(value), *_TOKEN_RE.findall(value)):
                normalized = candidate.strip().casefold()
                if len(normalized) >= 6:
                    self._derived_values.add(normalized)

    def evaluate(self, tool_name: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        tool = str(tool_name)
        reasons: list[str] = []
        role_fields = SINK_TO_ROLE_FIELDS.get(tool, ())
        role_values = _flatten_role_values(arguments, role_fields)
        if self.has_capability and role_values:
            unauthorized = [
                value
                for value in role_values
                if value.casefold() not in self._user_text
            ]
            if unauthorized:
                reasons.append(
                    "capability role check failed for recipient/target: "
                    + ", ".join(unauthorized[:4])
                )
        if self.has_provenance and tool in PROVENANCE_SINKS:
            sink_text = " ".join(_strings(arguments)).casefold()
            leaked = sorted(
                value for value in self._derived_values
                if len(value) >= 8 and value in sink_text
            )
            if leaked:
                reasons.append(
                    "provenance sink blocked exact tool-derived value: "
                    + ", ".join(leaked[:4])
                )
        allowed = not reasons
        self.decisions.append(
            {"tool": tool, "allowed": allowed, "reason": "; ".join(reasons)}
        )
        return allowed, "; ".join(reasons) if reasons else "checks passed"


__all__ = ["AgentDojoGate", "PROVENANCE_SINKS", "SINK_TO_ROLE_FIELDS", "TRANSFER_DEFENSES"]
