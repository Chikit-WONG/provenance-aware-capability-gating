"""Deterministic capability and exact provenance gateway."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from .provenance import (
    TRUST_RANK,
    DetectedTaint,
    ExactTaintTracker,
    ProvenanceTag,
    RuntimeProvenance,
    SENSITIVITY_RANK,
)
from .schemas import (
    ArgumentContract,
    ArgumentRole,
    Capability,
    Decision,
    DefenseArm,
    EventKind,
    ParameterBound,
    Sensitivity,
    ToolContract,
    ToolName,
    TrustLevel,
)
from .tools import TOOL_ARGUMENT_MODELS, ToolExecutionResult, ToolExecutor
from .world import AuditLog


class GatewayDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason: str
    capability_id: str | None = None
    proposal_event_id: str
    policy_event_id: str
    detected_taints: tuple[DetectedTaint, ...] = ()
    argument_provenance: dict[str, ProvenanceTag] = Field(default_factory=dict)


class GuardedToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    decision: GatewayDecision
    execution: ToolExecutionResult | None = None


# SELECTOR arguments whose values identify world entities.  "date" is included
# so calendar searches are resource-scoped exactly the way the evaluator's
# ground truth already counts them (evaluator._argument_resource_ids).
_RESOURCE_ARGUMENTS = ("email_id", "file_id", "event_id", "date")

# Authority-binding policy interface (PACT-style, arXiv:2605.11039): each tool
# argument is assigned a semantic role.  TARGET arguments bind where authority
# is directed and are constrained by ``allowed_recipients``; SELECTOR arguments
# pick resources/dates and are constrained by ``allowed_resource_ids`` and
# ``parameter_bounds``; CONTENT arguments may carry external data but are
# scanned for registered protected values (the credential-egress check).  No
# mock-office tool exposes COMMAND/CREDENTIAL parameters; those roles exist for
# interface completeness.
ARGUMENT_ROLES: dict[ToolName, dict[str, ArgumentRole]] = {
    ToolName.SEARCH_EMAILS: {
        "query": ArgumentRole.CONTENT,
    },
    ToolName.READ_EMAIL: {
        "email_id": ArgumentRole.SELECTOR,
    },
    ToolName.READ_FILE: {
        "file_id": ArgumentRole.SELECTOR,
    },
    ToolName.SEARCH_CALENDAR: {
        "date": ArgumentRole.SELECTOR,
    },
    ToolName.SEND_EMAIL: {
        "to": ArgumentRole.TARGET,
        "cc": ArgumentRole.TARGET,
        "subject": ArgumentRole.CONTENT,
        "body": ArgumentRole.CONTENT,
    },
    ToolName.CREATE_CALENDAR_EVENT: {
        "title": ArgumentRole.CONTENT,
        "location": ArgumentRole.CONTENT,
        "start": ArgumentRole.SELECTOR,
        "end": ArgumentRole.SELECTOR,
        "participants": ArgumentRole.TARGET,
    },
}


ROLE_MINIMUM_TRUST: dict[ArgumentRole, TrustLevel] = {
    ArgumentRole.TARGET: TrustLevel.USER,
    ArgumentRole.COMMAND: TrustLevel.USER,
    ArgumentRole.CREDENTIAL: TrustLevel.TRUSTED,
    ArgumentRole.CONTENT: TrustLevel.EXTERNAL,
    ArgumentRole.SELECTOR: TrustLevel.TOOL_OUTPUT,
    ArgumentRole.CONTROL: TrustLevel.USER,
}


DEFAULT_TOOL_CONTRACTS: dict[ToolName, ToolContract] = {
    tool: ToolContract(
        tool=tool,
        arguments={
            name: ArgumentContract(
                role=role,
                minimum_trust=ROLE_MINIMUM_TRUST[role],
            )
            for name, role in arguments.items()
        },
    )
    for tool, arguments in ARGUMENT_ROLES.items()
}


def validate_tool_contracts(
    contracts: Mapping[ToolName, ToolContract],
) -> None:
    """Fail if a tool or schema argument lacks an explicit role contract."""

    if set(contracts) != set(TOOL_ARGUMENT_MODELS):
        missing = sorted(tool.value for tool in set(TOOL_ARGUMENT_MODELS) - set(contracts))
        extra = sorted(tool.value for tool in set(contracts) - set(TOOL_ARGUMENT_MODELS))
        raise ValueError(f"tool contract coverage mismatch; missing={missing}, extra={extra}")
    for tool, argument_model in TOOL_ARGUMENT_MODELS.items():
        contract = contracts[tool]
        if contract.tool is not tool:
            raise ValueError(f"contract key/tool mismatch for {tool.value}")
        schema_fields = set(argument_model.model_fields)
        contract_fields = set(contract.arguments)
        if schema_fields != contract_fields:
            missing = sorted(schema_fields - contract_fields)
            extra = sorted(contract_fields - schema_fields)
            raise ValueError(
                f"argument contract coverage mismatch for {tool.value}; "
                f"missing={missing}, extra={extra}"
            )


validate_tool_contracts(DEFAULT_TOOL_CONTRACTS)


def fields_for_role(tool: ToolName, *roles: ArgumentRole) -> tuple[str, ...]:
    """Return the declared argument names of ``tool`` carrying any of ``roles``."""

    return tuple(
        name for name, role in ARGUMENT_ROLES.get(tool, {}).items() if role in roles
    )


# Exact protected-value egress checks apply to CONTENT-role fields: external
# data may flow there, registered protected values may not.
_SINK_FIELDS: dict[ToolName, tuple[str, ...]] = {
    tool: fields_for_role(tool, ArgumentRole.CONTENT)
    for tool in (ToolName.SEND_EMAIL, ToolName.CREATE_CALENDAR_EVENT)
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
        runtime_provenance: RuntimeProvenance | None = None,
        tool_contracts: Mapping[ToolName, ToolContract] | None = None,
    ) -> None:
        self.defense_arm = DefenseArm(defense_arm)
        self.capabilities = tuple(capability.model_copy(deep=True) for capability in capabilities)
        identifiers = [capability.capability_id for capability in self.capabilities]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("capability_id values must be unique")
        self.audit_log = audit_log
        self.taint_tracker = taint_tracker or ExactTaintTracker()
        self.runtime_provenance = runtime_provenance
        self.tool_contracts = dict(tool_contracts or DEFAULT_TOOL_CONTRACTS)
        if self.defense_arm is DefenseArm.PACT_L2:
            validate_tool_contracts(self.tool_contracts)
            if self.runtime_provenance is None:
                self.runtime_provenance = RuntimeProvenance()
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

        if self.defense_arm in (
            DefenseArm.PROVENANCE_ONLY,
            DefenseArm.PROMPT_PROVENANCE_ONLY,
        ):
            taints = self._provenance_violations(
                tool_name, arguments, Sensitivity.PUBLIC
            )
            if taints:
                identifiers = ", ".join(taint.protected_id for taint in taints)
                return self._record_decision(
                    actor=actor,
                    tool=tool_name,
                    arguments=arguments,
                    proposal_event_id=proposal.event_id,
                    allowed=False,
                    reason=(
                        "protected values exceed maximum outbound sensitivity "
                        f"{Sensitivity.PUBLIC.value}: {identifiers}"
                    ),
                    taints=taints,
                )
            return self._record_decision(
                actor=actor,
                tool=tool_name,
                arguments=arguments,
                proposal_event_id=proposal.event_id,
                allowed=True,
                reason=f"{self.defense_arm.value} provenance checks passed",
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
        all_argument_provenance: dict[str, ProvenanceTag] = {}
        for capability in candidates:
            violations, taints = self._capability_violations(capability, tool_name, arguments)
            argument_provenance: dict[str, ProvenanceTag] = {}
            if self.defense_arm is DefenseArm.PACT_L2:
                pact_violations, argument_provenance = self._pact_contract_violations(
                    tool_name, arguments
                )
                violations.extend(pact_violations)
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
                    argument_provenance=argument_provenance,
                )
            failures.append(f"{capability.capability_id}: {'; '.join(violations)}")
            all_taints = tuple(
                {taint.protected_id: taint for taint in (*all_taints, *taints)}.values()
            )
            all_argument_provenance.update(argument_provenance)

        return self._record_decision(
            actor=actor,
            tool=tool_name,
            arguments=arguments,
            proposal_event_id=proposal.event_id,
            allowed=False,
            reason=" | ".join(failures),
            taints=all_taints,
            argument_provenance=all_argument_provenance,
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
            DefenseArm.PACT_L2,
        ):
            taints = self.taint_tracker.scan_fields(
                arguments, _SINK_FIELDS.get(tool, ())
            )
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

    def _pact_contract_violations(
        self,
        tool: ToolName,
        arguments: Mapping[str, Any],
    ) -> tuple[list[str], dict[str, ProvenanceTag]]:
        """Apply role-specific provenance checks to every supplied argument."""

        if self.runtime_provenance is None:
            return ["PACT-L2 runtime provenance is unavailable"], {}
        contract = self.tool_contracts.get(tool)
        if contract is None:
            return [f"no argument contract for tool {tool.value}"], {}

        violations: list[str] = []
        resolved: dict[str, ProvenanceTag] = {}
        for name, value in arguments.items():
            argument_contract = contract.arguments.get(name)
            if argument_contract is None:
                violations.append(f"argument {name} has no role contract")
                continue
            tag = self.runtime_provenance.resolve(
                value,
                role=argument_contract.role,
            )
            resolved[name] = tag
            if TRUST_RANK[tag.trust] < TRUST_RANK[argument_contract.minimum_trust]:
                origins = ", ".join(tag.origins) or "unknown"
                violations.append(
                    f"{argument_contract.role.value} argument {name} requires "
                    f"{argument_contract.minimum_trust.value} trust, got "
                    f"{tag.trust.value} from {origins}"
                )
        return violations, resolved

    def _provenance_violations(
        self,
        tool: ToolName,
        arguments: Mapping[str, Any],
        maximum_sensitivity: Sensitivity,
    ) -> tuple[DetectedTaint, ...]:
        """Return protected sink taints above a no-capability sensitivity limit."""

        if tool not in _SINK_FIELDS:
            return ()
        taints = self.taint_tracker.scan_fields(arguments, _SINK_FIELDS[tool])
        return tuple(
            taint
            for taint in taints
            if SENSITIVITY_RANK[taint.sensitivity]
            > SENSITIVITY_RANK[maximum_sensitivity]
        )

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
        argument_provenance: Mapping[str, ProvenanceTag] | None = None,
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
            argument_provenance=dict(argument_provenance or {}),
        )
