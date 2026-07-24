"""Fresh-world, append-only orchestration of one Reader/Action benchmark run."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from .agents import (
    ActionAgent,
    ActionResult,
    AgentProtocolError,
    ReaderAgent,
    ReaderResult,
)
from .conditions import materialize_condition
from .evaluator import evaluate_run
from .model_client import (
    ChatModel,
    ModelClientError,
    ModelHTTPError,
    ModelResponseError,
    ModelTimeoutError,
    ToolCallParseError,
)
from .policy import CapabilityGateway
from .provenance import ExactTaintTracker, RuntimeProvenance
from .schemas import (
    AuditEvent,
    EventKind,
    RunResult,
    RunSpec,
    ScenarioSpec,
    UsageStats,
    WorldState,
)
from .secrets import SecretBroker
from .tools import ToolExecutor
from .world import AuditLog, MockWorld


class OrchestrationOutcome(BaseModel):
    """Complete in-memory evidence for one immutable attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_spec: RunSpec
    result: RunResult
    world_before: WorldState
    world_after: WorldState
    audit_events: tuple[AuditEvent, ...]
    final_response: str = ""
    reader_result: ReaderResult | None = None
    action_result: ActionResult | None = None


class ExperimentOrchestrator:
    """Run the two Agents with a new world, gateway, tracker, and audit each time.

    The model client may be shared across calls, but no mutable world/policy
    object is.  Persisted attempt directories use exclusive creation; a retry
    therefore needs a new ``attempt_id`` and cannot overwrite prior evidence.
    """

    def __init__(
        self,
        model: ChatModel,
        *,
        artifact_root: str | Path | None = None,
        reader_max_model_calls: int = 6,
        action_max_model_calls: int = 8,
        reader_max_tokens: int = 768,
        action_max_tokens: int = 1024,
        temperature: float = 0.7,
        top_p: float = 0.8,
        secret_broker_enabled: bool = False,
    ) -> None:
        self.model = model
        self.artifact_root = Path(artifact_root) if artifact_root is not None else None
        self.reader_max_model_calls = reader_max_model_calls
        self.action_max_model_calls = action_max_model_calls
        self.reader_max_tokens = reader_max_tokens
        self.action_max_tokens = action_max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.secret_broker_enabled = secret_broker_enabled

    def run(
        self,
        scenario: ScenarioSpec,
        run_spec: RunSpec,
        *,
        payload_base_dir: str | Path | None = None,
        attempt_id: str = "attempt-0001",
    ) -> OrchestrationOutcome:
        if scenario.scenario_id != run_spec.scenario_id:
            raise ValueError(
                f"scenario ID {scenario.scenario_id!r} does not match "
                f"RunSpec {run_spec.scenario_id!r}"
            )
        _validate_attempt_id(attempt_id)
        if self.artifact_root is not None:
            reserved_path = self.artifact_root / self._attempt_relative_dir(
                run_spec, attempt_id
            )
            if reserved_path.exists():
                raise FileExistsError(
                    f"append-only attempt already exists: {reserved_path}"
                )

        # materialize_condition returns a deep, condition-specific state.  This
        # operation happens on every call, including retries.
        initial_state = materialize_condition(
            scenario,
            run_spec.content_condition,
            payload_base_dir=payload_base_dir,
        )
        world = MockWorld(initial_state)
        world_before = world.snapshot()
        audit_log = AuditLog()
        taint_tracker = ExactTaintTracker(scenario.protected_values)
        runtime_provenance = RuntimeProvenance()
        runtime_provenance.observe_user_input(scenario.user_request)
        secret_broker = (
            SecretBroker.from_protected_values(scenario.protected_values)
            if self.secret_broker_enabled
            else None
        )
        executor = ToolExecutor(
            world,
            audit_log,
            taint_tracker,
            runtime_provenance=runtime_provenance,
            secret_broker=secret_broker,
        )
        gateway = CapabilityGateway(
            run_spec.defense_arm,
            scenario.capabilities,
            audit_log,
            taint_tracker,
            runtime_provenance=runtime_provenance,
            secret_broker=secret_broker,
        )

        reader_result: ReaderResult | None = None
        action_result: ActionResult | None = None
        final_response = ""
        valid = True
        invalid_reason = ""
        model_error = ""
        started = time.perf_counter()

        try:
            reader_result = ReaderAgent(
                self.model,
                executor,
                audit_log,
                defense_arm=run_spec.defense_arm,
                max_model_calls=self.reader_max_model_calls,
                max_tokens=self.reader_max_tokens,
                temperature=self.temperature,
                top_p=self.top_p,
            ).run(scenario.user_request, seed=run_spec.seed)
            action_result = ActionAgent(
                self.model,
                executor,
                gateway,
                audit_log,
                defense_arm=run_spec.defense_arm,
                max_model_calls=self.action_max_model_calls,
                max_tokens=self.action_max_tokens,
                temperature=self.temperature,
                top_p=self.top_p,
            ).run(
                scenario.user_request,
                reader_result,
                seed=run_spec.seed,
            )
            final_response = action_result.final_response
        except ModelClientError as exc:
            valid = False
            invalid_reason = _model_failure_reason(exc)
            model_error = str(exc)
            audit_log.append(
                EventKind.INFRASTRUCTURE,
                "orchestrator",
                reason=invalid_reason,
                success=False,
            )
        except AgentProtocolError as exc:
            valid = False
            invalid_reason = "agent_protocol_error"
            model_error = str(exc)
            audit_log.append(
                EventKind.INFRASTRUCTURE,
                "orchestrator",
                reason=invalid_reason,
                success=False,
            )

        latency = time.perf_counter() - started
        world_after = world.snapshot()
        usage = _usage_stats(
            reader_result,
            action_result,
            audit_log.events,
            latency_seconds=latency,
        )
        if secret_broker is not None:
            # Runtime hand-off may use opaque references, but completed traces
            # are display-only evidence and should not retain even those handles.
            if reader_result is not None:
                reader_result = ReaderResult.model_validate(
                    secret_broker.redact_for_display(
                        reader_result.model_dump(mode="python")
                    )
                )
            if action_result is not None:
                action_result = ActionResult.model_validate(
                    secret_broker.redact_for_display(
                        action_result.model_dump(mode="python")
                    )
                )
        artifact_paths = self._artifact_paths(run_spec, attempt_id)
        result = evaluate_run(
            scenario,
            world_before,
            world_after,
            audit_log.events,
            final_response,
            valid=valid,
            invalid_reason=invalid_reason,
            run_spec=run_spec,
            usage=usage,
            artifact_paths=artifact_paths,
            model_error=model_error,
        )
        outcome = OrchestrationOutcome(
            run_spec=run_spec,
            result=result,
            world_before=world_before,
            world_after=world_after,
            audit_events=audit_log.events,
            final_response=final_response,
            reader_result=reader_result,
            action_result=action_result,
        )
        if self.artifact_root is not None:
            self._persist(outcome, attempt_id)
        return outcome

    # Explicit name used by experiment drivers.
    run_attempt = run

    def _attempt_relative_dir(self, run_spec: RunSpec, attempt_id: str) -> Path:
        return Path(run_spec.run_id) / attempt_id

    def _artifact_paths(self, run_spec: RunSpec, attempt_id: str) -> dict[str, str]:
        if self.artifact_root is None:
            return {}
        directory = self._attempt_relative_dir(run_spec, attempt_id)
        names = {
            "run_spec": "run_spec.json",
            "world_before": "world_before.json",
            "world_after": "world_after.json",
            "audit": "audit.jsonl",
            "final_response": "final_response.json",
            "result": "result.json",
            "record": "record.json",
        }
        return {key: (directory / name).as_posix() for key, name in names.items()}

    def _persist(self, outcome: OrchestrationOutcome, attempt_id: str) -> None:
        assert self.artifact_root is not None
        relative_dir = self._attempt_relative_dir(outcome.run_spec, attempt_id)
        attempt_dir = self.artifact_root / relative_dir
        # Parents may be shared by attempts; the leaf must be new.
        attempt_dir.parent.mkdir(parents=True, exist_ok=True)
        attempt_dir.mkdir(exist_ok=False)

        _write_json_exclusive(attempt_dir / "run_spec.json", outcome.run_spec)
        _write_json_exclusive(attempt_dir / "world_before.json", outcome.world_before)
        _write_json_exclusive(attempt_dir / "world_after.json", outcome.world_after)
        with (attempt_dir / "audit.jsonl").open("x", encoding="utf-8") as handle:
            for event in outcome.audit_events:
                handle.write(event.model_dump_json())
                handle.write("\n")
        _write_json_exclusive(
            attempt_dir / "final_response.json",
            {"final_response": outcome.final_response},
        )
        if outcome.reader_result is not None:
            _write_json_exclusive(attempt_dir / "reader_trace.json", outcome.reader_result)
        if outcome.action_result is not None:
            _write_json_exclusive(attempt_dir / "action_trace.json", outcome.action_result)
        _write_json_exclusive(attempt_dir / "result.json", outcome.result)

        # Flat record supports direct JSONL aggregation while retaining the two
        # authoritative component files above.
        record = {
            **outcome.run_spec.model_dump(mode="json"),
            **outcome.result.model_dump(mode="json"),
            "attempt_id": attempt_id,
        }
        _write_json_exclusive(attempt_dir / "record.json", record)


def run_scenario(
    model: ChatModel,
    scenario: ScenarioSpec,
    run_spec: RunSpec,
    **kwargs: Any,
) -> OrchestrationOutcome:
    """One-shot convenience wrapper for callers that do not need configuration."""

    orchestrator_keys = {
        key: kwargs.pop(key)
        for key in tuple(kwargs)
        if key
        in {
            "artifact_root",
            "reader_max_model_calls",
            "action_max_model_calls",
            "reader_max_tokens",
            "action_max_tokens",
            "temperature",
            "top_p",
            "secret_broker_enabled",
        }
    }
    return ExperimentOrchestrator(model, **orchestrator_keys).run(
        scenario, run_spec, **kwargs
    )


def _model_failure_reason(error: ModelClientError) -> str:
    if isinstance(error, ModelTimeoutError):
        return "model_timeout"
    if isinstance(error, ModelHTTPError):
        return "model_http_error"
    if isinstance(error, ToolCallParseError):
        return "tool_call_parse_error"
    if isinstance(error, ModelResponseError):
        return "model_response_error"
    return "model_client_error"


def _usage_stats(
    reader: ReaderResult | None,
    action: ActionResult | None,
    events: tuple[AuditEvent, ...],
    *,
    latency_seconds: float,
) -> UsageStats:
    reader_usage = reader.usage if reader is not None else None
    action_usage = action.usage if action is not None else None
    # Audit-based counting remains meaningful when an Agent fails before it can
    # return its final trace.
    audited_reader_calls = sum(
        event.actor == "reader_agent"
        and event.event_kind in (EventKind.RESOURCE_READ, EventKind.TOOL_ERROR)
        for event in events
    )
    audited_action_calls = sum(
        event.actor == "action_agent" and event.event_kind == EventKind.TOOL_PROPOSAL
        for event in events
    )
    reported_tool_calls = (reader_usage.tool_calls if reader_usage else 0) + (
        action_usage.tool_calls if action_usage else 0
    )
    return UsageStats(
        reader_prompt_tokens=reader_usage.prompt_tokens if reader_usage else 0,
        reader_completion_tokens=reader_usage.completion_tokens if reader_usage else 0,
        action_prompt_tokens=action_usage.prompt_tokens if action_usage else 0,
        action_completion_tokens=action_usage.completion_tokens if action_usage else 0,
        model_calls=(reader_usage.model_calls if reader_usage else 0)
        + (action_usage.model_calls if action_usage else 0),
        tool_calls=max(reported_tool_calls, audited_reader_calls + audited_action_calls),
        latency_seconds=latency_seconds,
    )


def _validate_attempt_id(attempt_id: str) -> None:
    path = Path(attempt_id)
    if (
        not attempt_id
        or path.is_absolute()
        or len(path.parts) != 1
        or attempt_id in {".", ".."}
    ):
        raise ValueError("attempt_id must be one non-empty path component")


def _write_json_exclusive(path: Path, value: BaseModel | dict[str, Any]) -> None:
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json")
    else:
        payload = value
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")


# Concise alias for interactive/demo code.
Orchestrator = ExperimentOrchestrator


__all__ = [
    "ExperimentOrchestrator",
    "OrchestrationOutcome",
    "Orchestrator",
    "run_scenario",
]
