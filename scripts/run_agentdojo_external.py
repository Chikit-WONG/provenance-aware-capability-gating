#!/usr/bin/env python3
"""Execute one explicit slice of the frozen native AgentDojo plan.

AgentDojo is imported lazily because the controller/test environment does not
install it.  Every invocation owns a new append-only attempt leaf and an
independent official-trace root; no benchmark-wide Cartesian helper is used.
"""

from __future__ import annotations

import argparse
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


MODEL_NAMES = {"qwen3-vl-8b": "Qwen"}


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


def build_pipeline(arm: str, *, port: int) -> Any:
    """Build exactly the official configured victim pipeline for one arm."""

    if arm not in {"none", "repeat_user_prompt"}:
        raise ValueError("arm must be none or repeat_user_prompt")
    os.environ["LOCAL_LLM_PORT"] = str(port)
    AgentPipeline, PipelineConfig, models = _import_pipeline_types()
    MODEL_NAMES["qwen3-vl-8b"] = "Qwen"
    models.MODEL_NAMES["qwen3-vl-8b"] = "Qwen"
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm="vllm_parsed",
            model_id=None,
            defense=None if arm == "none" else "repeat_user_prompt",
            system_message_name=None,
            system_message=None,
            tool_delimiter="tool",
            tool_output_format="json",
        )
    )
    pipeline.name = f"qwen3-vl-8b__{arm}"
    return pipeline


def _benchmark_functions() -> tuple[Callable[..., Any], Callable[..., Any], Any]:
    """Resolve the official task functions without the Cartesian suite helper."""

    benchmark = importlib.import_module("agentdojo.benchmark")
    with_injection = getattr(benchmark, "run_task_with_injection_tasks")
    without_injection = getattr(benchmark, "run_task_without_injection_tasks")
    suite_module = importlib.import_module("agentdojo.task_suite")
    suite = suite_module.get_suite("v1.2.2", "workspace")
    return with_injection, without_injection, suite


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


def _call_task(function: Callable[..., Any], pipeline: Any, suite: Any, row: AgentDojoRunSpec) -> Any:
    """Call a native task function while preserving force_rerun=False."""

    injection_ids = [row.injection_task_id] if row.injection_task_id is not None else []
    kwargs = {"force_rerun": False}
    # The pinned API uses (suite, pipeline, user_task_id, injection_task_ids),
    # but accepting a named form keeps this adapter usable with minor API
    # spelling differences in the isolated environment.
    try:
        if row.attack == "none":
            return function(suite, pipeline, row.user_task_id, **kwargs)
        return function(suite, pipeline, row.user_task_id, injection_ids, **kwargs)
    except TypeError as first_error:
        try:
            if row.attack == "none":
                return function(pipeline, suite, row.user_task_id, **kwargs)
            return function(pipeline, suite, row.user_task_id, injection_ids, **kwargs)
        except TypeError:
            raise first_error


def _extract_metrics(value: Any) -> tuple[bool | None, bool | None, str]:
    """Extract utility/security/error while retaining opaque native output."""

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


def run_row(
    row: AgentDojoRunSpec,
    *,
    pipeline: Any,
    artifact_root: str | Path,
    attempt_id: str = "attempt-0001",
    suite_functions: tuple[Callable[..., Any], Callable[..., Any], Any] | None = None,
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
            with_injection, without_injection, suite = suite_functions or _benchmark_functions()
            native = _call_task(
                with_injection if row.attack != "none" else without_injection,
                pipeline,
                suite,
                row,
            )
        utility, security, error_text = _extract_metrics(native)
        if error_text:
            valid = False
            invalid_reason = "official_trace_error"
    except BaseException as exc:  # persist complete wrapper evidence for all failures
        valid = False
        invalid_reason = _failure_reason(exc)
        error_text = f"{type(exc).__name__}: {exc}"
    trace_hash = _hash_path(trace_root) if any(trace_root.rglob("*")) else ""
    trace_path = trace_root.relative_to(Path(artifact_root)).as_posix()
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
        arm = row.defense
        pipeline = pipelines.setdefault(arm, build_pipeline(arm, port=port))
        record_path = Path(artifact_root) / "runs" / row.run_id / attempt_id / "record.json"
        if resume and record_path.is_file():
            try:
                record = AgentDojoResultRecord.model_validate(json.loads(record_path.read_text()))
                if record.run_spec == row and record.attempt_id == attempt_id:
                    outputs.append(record)
                    continue
            except Exception:
                pass
        outputs.append(run_row(row, pipeline=pipeline, artifact_root=artifact_root, attempt_id=attempt_id))
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
