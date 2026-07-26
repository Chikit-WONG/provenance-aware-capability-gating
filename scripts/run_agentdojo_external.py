#!/usr/bin/env python3
"""Execute one explicit slice of the frozen native AgentDojo plan.

AgentDojo is imported lazily because the controller/test environment does not
install it.  Every invocation owns a new append-only attempt leaf and an
independent official-trace root; no benchmark-wide Cartesian helper is used.
"""

from __future__ import annotations

import argparse
import datetime
import enum
import hashlib
import importlib
import inspect
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentsec.agentdojo_external import AgentDojoResultRecord, AgentDojoRunSpec  # noqa: E402
from agentsec.agentdojo_guard import AgentDojoGate  # noqa: E402


MODEL_NAMES = {"qwen3-vl-8b": "Qwen"}


def _json_dumps_with_temporal_support(value: Any, *args: Any, default: Callable[[Any], Any] | None = None, **kwargs: Any) -> str:
    """Serialize AgentDojo JSON tool payloads without losing datetime values.

    AgentDojo 0.1.35 builds JSON tool messages from ``model_dump()`` in Python
    mode.  Workspace objects therefore contain ``datetime``/``date`` values,
    which the stock ``json.dumps`` call cannot encode.  Keep the public JSON
    format, but encode temporal values as ISO-8601 strings and retain any
    caller-provided fallback for other custom objects.
    """

    def _default(obj: Any) -> Any:
        if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
            return obj.isoformat()
        if isinstance(obj, enum.Enum):
            return obj.value
        if isinstance(obj, Path):
            return obj.as_posix()
        try:
            from pydantic import BaseModel

            if isinstance(obj, BaseModel):
                return obj.model_dump(mode="json")
        except ImportError:
            pass
        if default is not None:
            converted = default(obj)
            if converted is not obj:
                return converted
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    kwargs["default"] = _default
    return json.dumps(value, *args, **kwargs)


def _json_tool_result_to_str(tool_result: Any) -> str:
    """Match AgentDojo's JSON formatter while supporting temporal fields."""

    from pydantic import BaseModel

    if isinstance(tool_result, BaseModel):
        value: Any = tool_result.model_dump()
    elif isinstance(tool_result, list):
        items: list[Any] = []
        for item in tool_result:
            if type(item) in (str, int):
                items.append(str(item))
            elif isinstance(item, BaseModel):
                items.append(item.model_dump())
            else:
                raise TypeError("Not valid type for item tool result: " + str(type(item)))
        value = items
    else:
        return str(tool_result)
    return _json_dumps_with_temporal_support(value).strip()


def _patch_json_tool_formatters(pipeline: Any) -> int:
    """Patch only AgentDojo ToolsExecutor nodes to use the safe JSON formatter."""

    patched = 0
    visited: set[int] = set()

    def visit(node: Any) -> None:
        nonlocal patched
        marker = id(node)
        if marker in visited:
            return
        visited.add(marker)
        if node.__class__.__name__ == "ToolsExecutor" and hasattr(node, "output_formatter"):
            node.output_formatter = _json_tool_result_to_str
            patched += 1
        for child in getattr(node, "elements", ()) or ():
            visit(child)

    visit(pipeline)
    if patched == 0:
        raise RuntimeError("AgentDojo pipeline has no ToolsExecutor to patch")
    return patched


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    elif path.is_dir():
        for item in sorted(path.rglob("*"), key=lambda p: p.relative_to(path).as_posix()):
            if item.is_file():
                digest.update(item.relative_to(path).as_posix().encode())
                with item.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
    return digest.hexdigest()


def load_plan(plan_path: str | Path, phase: str) -> list[AgentDojoRunSpec]:
    rows = [
        AgentDojoRunSpec.model_validate(json.loads(line))
        for line in Path(plan_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if phase not in {"development", "formal"}:
        raise ValueError("phase must be development or formal")
    selected = [row for row in rows if row.phase == phase]
    if len({row.run_id for row in selected}) != len(selected):
        raise ValueError("frozen plan contains duplicate run IDs")
    return selected


def _import_pipeline_types() -> tuple[Any, Any, Any]:
    pipeline_module = importlib.import_module("agentdojo.agent_pipeline")
    AgentPipeline = getattr(pipeline_module, "AgentPipeline")
    PipelineConfig = getattr(pipeline_module, "PipelineConfig", None)
    if PipelineConfig is None:
        for module_name in ("agentdojo.pipeline_config", "agentdojo.models"):
            try:
                PipelineConfig = getattr(importlib.import_module(module_name), "PipelineConfig")
                break
            except (ImportError, AttributeError):
                continue
    if PipelineConfig is None:
        raise ImportError("AgentDojo PipelineConfig is unavailable")
    models = importlib.import_module("agentdojo.models")
    return AgentPipeline, PipelineConfig, models



def _install_guarded_executor(pipeline: Any, gate: AgentDojoGate) -> None:
    """Replace native ToolsExecutor nodes with a runtime-proxy gate."""
    pipeline_module = importlib.import_module("agentdojo.agent_pipeline")
    tools_executor_type = getattr(pipeline_module, "ToolsExecutor")

    class _GatedRuntime:
        def __init__(self, runtime: Any) -> None:
            self._runtime = runtime

        @property
        def functions(self) -> Any:
            return self._runtime.functions

        def run_function(self, env: Any, function: str, kwargs: Mapping[str, Any], raise_on_error: bool = False) -> Any:
            allowed, reason = gate.evaluate(function, kwargs)
            if not allowed:
                if raise_on_error:
                    raise RuntimeError(f"AgentDojoGateDenied: {reason}")
                return "", f"AgentDojoGateDenied: {reason}"
            result, error = self._runtime.run_function(env, function, kwargs, raise_on_error=raise_on_error)
            if error is None:
                gate.observe_tool_output(function, result)
            return result, error

    class _GatedToolsExecutor(tools_executor_type):
        def query(self, query: str, runtime: Any, env: Any = None, messages: Sequence[Mapping[str, Any]] = (), extra_args: dict = None) -> Any:
            gate.observe_messages(messages)
            return super().query(query, _GatedRuntime(runtime), env, messages, extra_args or {})


    def replace(node: Any) -> Any:
        if node.__class__.__name__ == "ToolsExecutor":
            guarded = _GatedToolsExecutor(node.output_formatter)
            return guarded
        children = getattr(node, "elements", None)
        if isinstance(children, list):
            node.elements = [replace(child) for child in children]
        return node

    replace(pipeline)

def build_pipeline(arm: str, *, port: int, gate: AgentDojoGate | None = None) -> Any:
    """Build exactly the official configured victim pipeline for one arm."""
    valid_arms = {
        "none", "repeat_user_prompt", "capability_only", "provenance_only",
        "prompt_capability", "prompt_provenance", "full",
    }
    if arm not in valid_arms:
        raise ValueError(f"unsupported AgentDojo defense arm: {arm}")
    os.environ["LOCAL_LLM_PORT"] = str(port)
    AgentPipeline, PipelineConfig, models = _import_pipeline_types()
    MODEL_NAMES["qwen3-vl-8b"] = "Qwen"
    models.MODEL_NAMES["qwen3-vl-8b"] = "Qwen"
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm="vllm_parsed",
            model_id=None,
            defense=None if arm in {"none", "capability_only", "provenance_only", "full"} else "repeat_user_prompt",
            system_message_name=None,
            system_message=None,
            tool_delimiter="tool",
            tool_output_format="json",
        )
    )
    _patch_json_tool_formatters(pipeline)
    if gate is not None:
        _install_guarded_executor(pipeline, gate)
    pipeline.name = f"qwen3-vl-8b__{arm}"
    return pipeline


def _benchmark_functions(pipeline: Any | None = None, attack_name: str | None = None, suite_name: str = "workspace") -> tuple[Any, Any, Any, Any | None]:
    """Resolve the official task functions and suite/attack objects lazily."""

    benchmark = importlib.import_module("agentdojo.benchmark")
    with_injection = getattr(benchmark, "run_task_with_injection_tasks")
    without_injection = getattr(benchmark, "run_task_without_injection_tasks")
    suite_module = importlib.import_module("agentdojo.task_suite")
    suite = suite_module.get_suite("v1.2.2", suite_name)
    attack = None
    if pipeline is not None and attack_name and attack_name != "none":
        attacks = importlib.import_module("agentdojo.attacks")
        attack = attacks.load_attack(attack_name, suite, pipeline)
    return with_injection, without_injection, suite, attack


def _output_logger() -> Any:
    for module_name in ("agentdojo.agent_pipeline", "agentdojo.logging", "agentdojo.utils"):
        try:
            module = importlib.import_module(module_name)
            logger = getattr(module, "OutputLogger", None)
            if logger is not None:
                return logger
        except ImportError:
            continue
    raise ImportError("AgentDojo OutputLogger is unavailable")


def _call_task(
    function: Callable[..., Any],
    pipeline: Any,
    suite: Any,
    row: AgentDojoRunSpec,
    *,
    attack: Any | None = None,
    logdir: Path | None = None,
) -> Any:
    """Call one pinned AgentDojo task function exactly once.

    AgentDojo 0.1.35 takes task objects, an attack object, a log directory,
    and a force-rerun flag.  The injection list is deliberately one element.
    """

    task = suite.get_user_task_by_id(row.user_task_id) if hasattr(suite, "get_user_task_by_id") else row.user_task_id
    log_path = logdir if logdir is not None else None
    if row.attack == "none":
        return function(
            suite, pipeline, task, log_path, force_rerun=False, benchmark_version="v1.2.2"
        )
    if attack is None:
        try:
            attacks = importlib.import_module("agentdojo.attacks")
            attack = attacks.load_attack(row.attack, suite, pipeline)
        except ModuleNotFoundError:
            # Unit-test adapters may supply a stub function without installing
            # AgentDojo; the pinned runner path resolves the attack above.
            attack = None
    injection_ids = [row.injection_task_id]
    return function(
        suite,
        pipeline,
        task,
        attack,
        log_path,
        force_rerun=False,
        injection_tasks=injection_ids,
        benchmark_version="v1.2.2",
    )


def _extract_metrics(value: Any) -> tuple[bool | None, bool | None, str]:
    """Extract utility/security/error while retaining opaque native output."""

    if isinstance(value, (tuple, list)) and len(value) >= 2:
        utility, security = value[0], value[1]
        if isinstance(utility, Mapping):
            utility = next(iter(utility.values()), None)
        if isinstance(security, Mapping):
            security = next(iter(security.values()), None)
        return (None if utility is None else bool(utility), None if security is None else bool(security), "")
    if isinstance(value, Mapping):
        utility = value.get("utility", value.get("utility_score"))
        security = value.get("security", value.get("targeted_attack_success"))
        error = str(value.get("error", "") or "")
        return (None if utility is None else bool(utility), None if security is None else bool(security), error)
    for names in (("utility", "utility_score"), ("security", "targeted_attack_success")):
        found = next((getattr(value, name) for name in names if hasattr(value, name)), None)
        if names[0] == "utility":
            utility = None if found is None else bool(found)
        else:
            security = None if found is None else bool(found)
    error = str(getattr(value, "error", "") or "")
    return utility, security, error


def _failure_reason(error: BaseException) -> str:
    name = type(error).__name__.casefold()
    if "timeout" in name or isinstance(error, TimeoutError):
        return "model_timeout"
    if isinstance(error, (ConnectionError, OSError)) or any(token in name for token in ("transport", "http", "connection")):
        return "local_endpoint_transport_failure"
    return "agentdojo_execution_error"


_KNOWN_RESULT_REASONS = {
    "model_timeout",
    "local_endpoint_transport_failure",
    "scheduler_termination",
    "artifact_write_interruption",
    "tool_call_parse_error",
    "refusal",
    "no_op",
    "evaluator_false",
    "defense_block",
    "agent_protocol_error",
}


def _result_reason(error_text: str) -> str:
    value = str(error_text or "").strip()
    return value if value in _KNOWN_RESULT_REASONS else "official_trace_error"


def run_row(
    row: AgentDojoRunSpec,
    *,
    pipeline: Any,
    artifact_root: str | Path,
    attempt_id: str = "attempt-0001",
    suite_functions: tuple[Callable[..., Any], Callable[..., Any], Any] | None = None,
    adapter_gate: AgentDojoGate | None = None,
) -> AgentDojoResultRecord:
    """Run and persist exactly one row in a fresh append-only attempt leaf."""

    if attempt_id not in {"attempt-0001", "attempt-0002"}:
        raise ValueError("attempt_id must be attempt-0001 or attempt-0002")
    leaf = Path(artifact_root) / "runs" / row.run_id / attempt_id
    leaf.parent.mkdir(parents=True, exist_ok=True)
    leaf.mkdir(exist_ok=False)
    trace_root = leaf / "official-traces" / attempt_id
    trace_root.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    utility: bool | None = None
    security: bool | None = None
    error_text = ""
    invalid_reason = ""
    valid = True
    try:
        with _output_logger()(str(trace_root)):
            resolved = suite_functions or _benchmark_functions(pipeline, row.attack, row.suite)
            with_injection, without_injection, suite = resolved[:3]
            attack = resolved[3] if len(resolved) > 3 else None
            native = _call_task(
                with_injection if row.attack != "none" else without_injection,
                pipeline,
                suite,
                row,
                attack=attack,
                logdir=trace_root,
            )
        utility, security, error_text = _extract_metrics(native)
        if error_text:
            valid = False
            invalid_reason = _result_reason(error_text)
        elif row.attack != "none" and (utility is None or security is None):
            valid = False
            invalid_reason = "official_result_missing_metric"
        elif row.attack == "none" and utility is None:
            valid = False
            invalid_reason = "official_result_missing_metric"
    except BaseException as exc:  # persist complete wrapper evidence for all failures
        valid = False
        invalid_reason = _failure_reason(exc)
        error_text = f"{type(exc).__name__}: {exc}"
    trace_hash = _hash_path(trace_root) if any(trace_root.rglob("*")) else ""
    trace_path = trace_root.relative_to(Path(artifact_root)).as_posix()
    adapter_decision_sha = ""
    if adapter_gate is not None:
        adapter_decision_sha = hashlib.sha256(json.dumps(adapter_gate.decisions, sort_keys=True).encode("utf-8")).hexdigest()
    record = AgentDojoResultRecord(
        **row.model_dump(),
        attempt_id=attempt_id,
        valid=valid,
        invalid_reason=invalid_reason,
        utility=utility,
        targeted_attack_success=security if row.attack != "none" else None,
        official_security_value=security if row.attack != "none" else None,
        official_trace_path=trace_path,
        trace_sha256=trace_hash,
        duration_seconds=time.perf_counter() - started,
        error=error_text,
        adapter_mode=adapter_gate.mode if adapter_gate is not None else "",
        adapter_denied_calls=sum(1 for decision in (adapter_gate.decisions if adapter_gate is not None else ()) if not decision["allowed"]),
        adapter_decision_sha256=adapter_decision_sha,
    )
    record_path = leaf / "record.json"
    with record_path.open("x", encoding="utf-8") as handle:
        handle.write(record.model_dump_json(indent=2))
        handle.write("\n")
    return record


def run_slice(
    plan_path: str | Path,
    artifact_root: str | Path,
    *,
    phase: str,
    start_index: int = 0,
    limit: int | None = None,
    attempt_id: str = "attempt-0001",
    resume: bool = False,
    port: int = 8000,
) -> list[AgentDojoResultRecord]:
    rows = load_plan(plan_path, phase)
    if start_index < 0 or start_index > len(rows):
        raise ValueError("start-index is out of range")
    selected = rows[start_index:] if limit is None else rows[start_index : start_index + limit]
    pipelines: dict[str, Any] = {}
    outputs: list[AgentDojoResultRecord] = []
    for row in selected:
        record_path = Path(artifact_root) / "runs" / row.run_id / attempt_id / "record.json"
        if resume and record_path.is_file():
            try:
                record = AgentDojoResultRecord.model_validate(json.loads(record_path.read_text()))
                if record.run_spec == row and record.attempt_id == attempt_id:
                    outputs.append(record)
                    continue
            except Exception:
                pass
        arm = row.defense
        transfer_arms = {"capability_only", "provenance_only", "prompt_capability", "prompt_provenance", "full"}
        gate = AgentDojoGate(arm) if arm in transfer_arms else None
        pipeline = None if gate is not None else pipelines.get(arm)
        if pipeline is None:
            pipeline = build_pipeline(arm, port=port, gate=gate)
            if gate is None:
                pipelines[arm] = pipeline
        outputs.append(run_row(row, pipeline=pipeline, artifact_root=artifact_root, attempt_id=attempt_id, adapter_gate=gate))
    return outputs


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--phase", choices=("development", "formal"), required=True)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--attempt-id", choices=("attempt-0001", "attempt-0002"), default="attempt-0001")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    records = run_slice(
        args.plan,
        args.artifact_root,
        phase=args.phase,
        start_index=args.start_index,
        limit=args.limit,
        attempt_id=args.attempt_id,
        resume=args.resume,
        port=args.port,
    )
    print(json.dumps({"record_count": len(records), "run_ids": [row.run_id for row in records]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
