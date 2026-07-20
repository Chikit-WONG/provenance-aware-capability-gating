"""Deterministic capability and exact provenance gateway."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict

from .provenance import DetectedTaint, ExactTaintTracker, SENSITIVITY_RANK
from .schemas import (
    Capability,
    Decision,
    DefenseArm,
    EventKind,
    ParameterBound,
    ToolName,
)
from .tools import ToolExecutionResult, ToolExecutor
from .world import AuditLog


class GatewayDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason: str
    capability_id: str | None = None
    proposal_event_id: str
    policy_event_id: str
    detected_taints: tuple[DetectedTaint, ...] = ()


class GuardedToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    decision: GatewayDecision
    execution: ToolExecutionResult | None = None


_RESOURCE_ARGUMENTS = ("email_id", "file_id", "event_id")
_SINK_FIELDS: dict[ToolName, tuple[str, ...]] = {
    ToolName.SEND_EMAIL: ("subject", "body"),
    ToolName.CREATE_CALENDAR_EVENT: ("title", "location"),
}


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone(timedelta(hours=8)))
    return parsed.astimezone(timezone.utc)


def _synthetic_parameter(name: str, arguments: Mapping[str, Any]) -> Any:
    if name != "duration_minutes":
        return arguments.get(name)
    start = arguments.get("start")
    end = arguments.get("end")
    if not isinstance(start, str) or not isinstance(end, str):
        return None
    start_time = _parse_iso_datetime(start)
    end_time = _parse_iso_datetime(end)
    if start_time is None or end_time is None:
        return None
    return (end_time - start_time).total_seconds() / 60.0


def _values_for_comparison(actual: Any, boundary: Any) -> tuple[Any, Any] | None:
    if isinstance(boundary, bool):
        return (actual, boundary) if isinstance(actual, bool) else None
    if isinstance(boundary, (int, float)) and not isinstance(boundary, bool):
        if not isinstance(actual, (int, float)) or isinstance(actual, bool):
            return None
        return float(actual), float(boundary)
    if isinstance(boundary, str) and isinstance(actual, str):
        parsed_actual = _parse_iso_datetime(actual)
        parsed_boundary = _parse_iso_datetime(boundary)
        if parsed_actual is not None and parsed_boundary is not None:
            return parsed_actual, parsed_boundary
        return actual, boundary
    return None


def _bound_violation(name: str, actual: Any, bound: ParameterBound) -> str | None:
    if actual is None:
        return f"missing bounded parameter {name}"
    if bound.allowed_values is not None and actual not in bound.allowed_values:
        return f"parameter {name}={actual!r} is outside allowed_values"
    if bound.minimum is not None:
        comparable = _values_for_comparison(actual, bound.minimum)
        if comparable is None:
            return f"parameter {name} has a type incompatible with its minimum"
        if comparable[0] < comparable[1]:
            return f"parameter {name}={actual!r} is below minimum {bound.minimum!r}"
    if bound.maximum is not None:
        comparable = _values_for_comparison(actual, bound.maximum)
        if comparable is None:
            return f"parameter {name} has a type incompatible with its maximum"
        if comparable[0] > comparable[1]:
            return f"parameter {name}={actual!r} exceeds maximum {bound.maximum!r}"
    return None


def _resource_ids(arguments: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(arguments[name])
        for name in _RESOURCE_ARGUMENTS
        if name in arguments and arguments[name] is not None
    )


def _recipients(tool: ToolName, arguments: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    if tool is ToolName.SEND_EMAIL:
        to = arguments.get("to")
        if isinstance(to, str):
            values.append(to)
        elif isinstance(to, (list, tuple)):
            values.extend(str(item) for item in to)
        cc = arguments.get("cc", ())
        if isinstance(cc, str):
            values.append(cc)
        elif isinstance(cc, (list, tuple)):
            values.extend(str(item) for item in cc)
    elif tool is ToolName.CREATE_CALENDAR_EVENT:
        participants = arguments.get("participants", ())
        if isinstance(participants, str):
            values.append(participants)
        elif isinstance(participants, (list, tuple)):
            values.extend(str(item) for item in participants)
    return tuple(values)


class CapabilityGateway:
    """Mediate Action-Agent proposals under an experiment defense arm."""

    def __init__(
        self,
        defense_arm: DefenseArm | str,
        capabilities: Iterable[Capability],
        audit_log: AuditLog,
        taint_tracker: ExactTaintTracker | None = None,
    ) -> None:
        self.defense_arm = DefenseArm(defense_arm)
        self.capabilities = tuple(capability.model_copy(deep=True) for capability in capabilities)
        identifiers = [capability.capability_id for capability in self.capabilities]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("capability_id values must be unique")
        self.audit_log = audit_log
        self.taint_tracker = taint_tracker or ExactTaintTracker()
        self._call_counts = {identifier: 0 for identifier in identifiers}

    @property
    def call_counts(self) -> dict[str, int]:
        return dict(self._call_counts)

    def evaluate(
        self,
        tool: ToolName | str,
        arguments: Mapping[str, Any],
        actor: str = "action_agent",
    ) -> GatewayDecision:
        arguments = dict(arguments)
        try:
            tool_name = ToolName(tool)
        except ValueError:
            proposal = self.audit_log.append(
                EventKind.TOOL_PROPOSAL,
                actor,
                arguments={"requested_tool": str(tool), **arguments},
                success=None,
            )
            return self._record_decision(
                actor=actor,
                tool=None,
                arguments=arguments,
                proposal_event_id=proposal.event_id,
                allowed=False,
                reason=f"unknown tool: {tool}",
            )

        proposal = self.audit_log.append(
            EventKind.TOOL_PROPOSAL,
            actor,
            tool=tool_name,
            arguments=arguments,
            resource_ids=_resource_ids(arguments),
        )

        if self.defense_arm in (DefenseArm.ALLOW_ALL, DefenseArm.PROMPT_ONLY):
            return self._record_decision(
                actor=actor,
                tool=tool_name,
                arguments=arguments,
                proposal_event_id=proposal.event_id,
                allowed=True,
                reason=f"{self.defense_arm.value} bypasses capability enforcement",
            )

        candidates = [capability for capability in self.capabilities if capability.tool is tool_name]
        if not candidates:
            return self._record_decision(
                actor=actor,
                tool=tool_name,
                arguments=arguments,
                proposal_event_id=proposal.event_id,
                allowed=False,
                reason=f"no capability grants tool {tool_name.value}",
            )

        failures: list[str] = []
        all_taints: tuple[DetectedTaint, ...] = ()
        for capability in candidates:
            violations, taints = self._capability_violations(capability, tool_name, arguments)
            if not violations:
                self._call_counts[capability.capability_id] += 1
                return self._record_decision(
                    actor=actor,
                    tool=tool_name,
                    arguments=arguments,
                    proposal_event_id=proposal.event_id,
                    allowed=True,
                    reason="capability checks passed",
                    capability_id=capability.capability_id,
                    taints=taints,
                )
            failures.append(f"{capability.capability_id}: {'; '.join(violations)}")
            all_taints = tuple(
                {taint.protected_id: taint for taint in (*all_taints, *taints)}.values()
            )

        return self._record_decision(
            actor=actor,
            tool=tool_name,
            arguments=arguments,
            proposal_event_id=proposal.event_id,
            allowed=False,
            reason=" | ".join(failures),
            taints=all_taints,
        )

    # Common names used by orchestrators; both have the same consuming semantics.
    authorize = evaluate
    check = evaluate

    def execute(
        self,
        executor: ToolExecutor,
        tool: ToolName | str,
        arguments: Mapping[str, Any],
        actor: str = "action_agent",
    ) -> GuardedToolResult:
        if executor.audit_log is not self.audit_log:
            raise ValueError("gateway and executor must share one AuditLog")
        decision = self.evaluate(tool, arguments, actor)
        if not decision.allowed:
            return GuardedToolResult(decision=decision)
        execution = executor.execute(tool, dict(arguments), actor)
        return GuardedToolResult(decision=decision, execution=execution)

    def _capability_violations(
        self, capability: Capability, tool: ToolName, arguments: Mapping[str, Any]
    ) -> tuple[list[str], tuple[DetectedTaint, ...]]:
        violations: list[str] = []
        if self._call_counts[capability.capability_id] >= capability.max_calls:
            violations.append(f"maximum call count {capability.max_calls} reached")

        actual_resources = _resource_ids(arguments)
        if capability.allowed_resource_ids is not None:
            allowed_resources = set(capability.allowed_resource_ids)
            disallowed = [item for item in actual_resources if item not in allowed_resources]
            if disallowed:
                violations.append(f"resources not allowed: {', '.join(disallowed)}")

        actual_recipients = _recipients(tool, arguments)
        if capability.allowed_recipients is not None:
            allowed_recipients = {
                recipient.strip().casefold() for recipient in capability.allowed_recipients
            }
            disallowed = [
                recipient
                for recipient in actual_recipients
                if recipient.strip().casefold() not in allowed_recipients
            ]
            if disallowed:
                violations.append(f"recipients not allowed: {', '.join(disallowed)}")

        for name, bound in capability.parameter_bounds.items():
            actual = _synthetic_parameter(name, arguments)
            violation = _bound_violation(name, actual, bound)
            if violation:
                violations.append(violation)

        taints: tuple[DetectedTaint, ...] = ()
        if self.defense_arm in (
            DefenseArm.CAPABILITY_PROVENANCE_ONLY,
            DefenseArm.FULL,
        ) and tool in _SINK_FIELDS:
            taints = self.taint_tracker.scan_fields(arguments, _SINK_FIELDS[tool])
            too_sensitive = [
                taint
                for taint in taints
                if SENSITIVITY_RANK[taint.sensitivity]
                > SENSITIVITY_RANK[capability.max_outbound_sensitivity]
            ]
            if too_sensitive:
                identifiers = ", ".join(taint.protected_id for taint in too_sensitive)
                violations.append(
                    "protected values exceed maximum outbound sensitivity "
                    f"{capability.max_outbound_sensitivity.value}: {identifiers}"
                )
        return violations, taints

    def _record_decision(
        self,
        *,
        actor: str,
        tool: ToolName | None,
        arguments: dict[str, Any],
        proposal_event_id: str,
        allowed: bool,
        reason: str,
        capability_id: str | None = None,
        taints: tuple[DetectedTaint, ...] = (),
    ) -> GatewayDecision:
        provenance = self.taint_tracker.provenance_for(
            taints, parent_event_ids=(proposal_event_id,)
        )
        event = self.audit_log.append(
            EventKind.POLICY_DECISION,
            actor="capability_gateway",
            tool=tool,
            arguments=arguments,
            resource_ids=_resource_ids(arguments),
            provenance=provenance,
            decision=Decision.ALLOW if allowed else Decision.DENY,
            reason=reason,
            success=allowed,
        )
        return GatewayDecision(
            allowed=allowed,
            reason=reason,
            capability_id=capability_id,
            proposal_event_id=proposal_event_id,
            policy_event_id=event.event_id,
            detected_taints=taints,
        )
