"""Real-tool-boundary adapter for the deterministic PACT policy core.

The adapter deliberately separates policy evaluation from side effects: a
capability-only run may execute an allow-listed value even when PACT rejects
its provenance, while a PACT run invokes ``ToolExecutor`` only after both
checks pass.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .pact import PACTArgument, PACTCall, PACTGateway
from .tools import ToolExecutionResult, ToolExecutor


PolicyName = Literal["capability_only", "pact"]


class PACTToolResult(BaseModel):
    """Structured evidence for one policy decision and possible tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    policy: PolicyName
    capability_allowed: bool
    pact_allowed: bool
    transformation_verified: bool = False
    enforced_allowed: bool
    executed: bool
    tool_ok: bool
    tool_event_id: str | None = None
    outbox_count: int = Field(ge=0)
    reason: str
    provenance_digests: dict[str, str]
    decision_log_sha256: str

    @property
    def execution_ok(self) -> bool:
        """Compatibility alias for the underlying tool execution status."""

        return self.tool_ok

    @property
    def event_id(self) -> str | None:
        """Compatibility alias for the underlying tool event ID."""

        return self.tool_event_id


class PACTToolGateway:
    """Apply PACT decisions at the existing ``ToolExecutor`` boundary."""

    def __init__(self, gateway: PACTGateway, tool_executor: ToolExecutor) -> None:
        self.gateway = gateway
        self.tool_executor = tool_executor

    def execute_send_email(
        self,
        call: PACTCall,
        case_id: str,
        policy: PolicyName,
    ) -> PACTToolResult:
        """Evaluate and, when allowed, execute one role-labelled email call.

        ``capability_only`` enforces only the ordinary value allow-list.
        ``pact`` enforces both the value allow-list and role/provenance policy.
        A denied PACT decision returns before ``ToolExecutor`` is touched, so
        it cannot create an audit mutation event or change the world's outbox.
        """

        if policy not in ("capability_only", "pact"):
            raise ValueError("policy must be 'capability_only' or 'pact'")
        if call.tool != "send_email":
            raise ValueError("execute_send_email only accepts the send_email tool")

        capability_allowed, capability_reason = self.gateway.capability_decision(call)
        pact_allowed, transformation_verified, pact_reason = self.gateway.pact_decision(call)
        enforced_allowed = capability_allowed if policy == "capability_only" else (
            capability_allowed and pact_allowed
        )
        reason = (
            f"capability: {capability_reason}; pact: {pact_reason}; "
            f"enforced policy {policy}: {'allow' if enforced_allowed else 'deny'}"
        )

        execution: ToolExecutionResult | None = None
        if enforced_allowed:
            execution = self.tool_executor.execute(
                "send_email",
                self._tool_arguments(call),
            )

        outbox_count = len(self.tool_executor.world.snapshot().outbox)
        executed = bool(execution is not None and execution.ok)
        tool_ok = bool(execution is not None and execution.ok)
        tool_event_id = execution.event_id if execution is not None else None
        provenance_digests = {
            name: argument.provenance.digest()
            for name, argument in call.arguments.items()
        }
        payload: dict[str, Any] = {
            "case_id": case_id,
            "policy": policy,
            "capability_allowed": capability_allowed,
            "pact_allowed": pact_allowed,
            "transformation_verified": transformation_verified,
            "enforced_allowed": enforced_allowed,
            "executed": executed,
            "tool_ok": tool_ok,
            "tool_event_id": tool_event_id,
            "outbox_count": outbox_count,
            "reason": reason,
            "provenance_digests": provenance_digests,
        }
        decision_hash = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        return PACTToolResult(**payload, decision_log_sha256=decision_hash)

    @staticmethod
    def _argument_for_role(call: PACTCall, role: str) -> PACTArgument | None:
        """Find a role-labelled argument, with a name fallback for callers."""

        for argument in call.arguments.values():
            if argument.role == role:
                return argument
        for argument in call.arguments.values():
            if argument.name == role:
                return argument
        return None

    @classmethod
    def _tool_arguments(cls, call: PACTCall) -> dict[str, Any]:
        recipient = cls._argument_for_role(call, "recipient")
        if recipient is None:
            raise ValueError("send_email call requires a recipient argument")
        content = cls._argument_for_role(call, "content")
        subject = cls._argument_for_role(call, "subject")
        return {
            "to": recipient.value,
            "subject": subject.value if subject is not None else "",
            "body": content.value if content is not None else "",
            "cc": (),
        }


__all__ = ["PACTToolGateway", "PACTToolResult", "PolicyName"]
