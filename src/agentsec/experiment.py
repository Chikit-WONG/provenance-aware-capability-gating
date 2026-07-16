"""Execution helpers for pilot, formal, and live-demo benchmark runs."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from .model_client import DEFAULT_BASE_URL, DEFAULT_MODEL_NAME, ChatModel, OpenAIModelClient
from .orchestrator import ExperimentOrchestrator, OrchestrationOutcome
from .runplan import FrozenRunPlanManifest, sha256_file, verify_frozen_plan
from .scenarios import load_scenario, load_scenarios
from .schemas import ContentCondition, DefenseArm, RunResult, RunSpec, ScenarioSpec


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class PlanExecutionSummary(BaseModel):
    """Counters from one controller session; individual evidence is authoritative."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    selected_n: int = Field(ge=0)
    executed_n: int = Field(ge=0)
    resumed_n: int = Field(ge=0)
    valid_n: int = Field(ge=0)
    invalid_n: int = Field(ge=0)
    result_paths: tuple[str, ...] = ()


def execute_run_plan(
    model: ChatModel,
    records: Sequence[RunSpec],
    scenarios: Sequence[ScenarioSpec],
    *,
    artifact_root: str | Path,
    payload_base_dir: str | Path | None = None,
    attempt_id: str = "attempt-0001",
    start_index: int = 0,
    limit: int | None = None,
    resume: bool = False,
    orchestrator_options: Mapping[str, Any] | None = None,
) -> PlanExecutionSummary:
    """Execute a stable slice while preserving every completed attempt.

    ``resume=True`` only accepts an already complete and schema-valid record;
    it never edits or retries inside an existing attempt directory.
    """

    if start_index < 0:
        raise ValueError("start_index must be non-negative")
    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative")
    root = Path(artifact_root)
    root.mkdir(parents=True, exist_ok=True)
    scenario_map = {scenario.scenario_id: scenario for scenario in scenarios}
    if len(scenario_map) != len(scenarios):
        raise ValueError("scenario IDs must be unique")
    selected = tuple(records[start_index : None if limit is None else start_index + limit])

    orchestrator = ExperimentOrchestrator(
        model, artifact_root=root, **dict(orchestrator_options or {})
    )
    results: list[RunResult] = []
    result_paths: list[str] = []
    executed_n = resumed_n = 0
    for ordinal, run_spec in enumerate(selected, start=start_index):
        if run_spec.scenario_id not in scenario_map:
            raise ValueError(f"run plan references unknown scenario {run_spec.scenario_id!r}")
        relative_result = Path(run_spec.run_id) / attempt_id / "result.json"
        result_path = root / relative_result
        if result_path.exists():
            if not resume:
                raise FileExistsError(
                    f"attempt already exists for plan index {ordinal}: {result_path}"
                )
            result = RunResult.model_validate_json(result_path.read_text(encoding="utf-8"))
            if result.run_id != run_spec.run_id:
                raise ValueError(f"existing result has wrong run_id: {result_path}")
            resumed_n += 1
        else:
            partial_dir = result_path.parent
            if partial_dir.exists():
                raise RuntimeError(
                    "incomplete prior attempt directory cannot be resumed or overwritten: "
                    f"{partial_dir}; use a new attempt_id"
                )
            outcome = orchestrator.run_attempt(
                scenario_map[run_spec.scenario_id],
                run_spec,
                payload_base_dir=payload_base_dir,
                attempt_id=attempt_id,
            )
            result = outcome.result
            executed_n += 1
        results.append(result)
        result_paths.append(relative_result.as_posix())
        print(
            json.dumps(
                {
                    "plan_index": ordinal,
                    "run_id": run_spec.run_id,
                    "scenario_id": run_spec.scenario_id,
                    "condition": run_spec.content_condition.value,
                    "defense": run_spec.defense_arm.value,
                    "valid": result.valid,
                    "executed_unauthorized_effect": result.executed_unauthorized_effect,
                    "secret_leakage": result.secret_leakage,
                    "benign_task_success": result.benign_task_success,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    return PlanExecutionSummary(
        selected_n=len(selected),
        executed_n=executed_n,
        resumed_n=resumed_n,
        valid_n=sum(result.valid for result in results),
        invalid_n=sum(not result.valid for result in results),
        result_paths=tuple(result_paths),
    )


def load_verified_formal_inputs(
    plan_dir: str | Path,
    corpus_dir: str | Path,
) -> tuple[FrozenRunPlanManifest, tuple[RunSpec, ...], tuple[ScenarioSpec, ...]]:
    """Verify both immutable manifests before any formal victim call."""

    manifest, records = verify_frozen_plan(plan_dir)
    corpus_root = Path(corpus_dir)
    corpus_manifest_path = corpus_root / "manifest.json"
    if sha256_file(corpus_manifest_path) != manifest.corpus_manifest_sha256:
        raise ValueError("frozen run plan references a different Red corpus manifest")
    from .redteam import load_frozen_scenarios  # avoids a hard generation dependency

    scenarios = load_frozen_scenarios(corpus_root)
    model_hashes = {record.model_config_hash for record in records}
    if model_hashes != {manifest.model_config_hash}:
        raise ValueError("verified plan contains model configuration drift")
    return manifest, records, scenarios


def run_demo_case(
    scenario_id: str = "T1",
    condition: str = "attack",
    defense: str = "full",
    seed: int = 4313,
    *,
    corpus_dir: str | Path | None = None,
    artifact_root: str | Path | None = None,
    base_url: str = DEFAULT_BASE_URL,
    model_name: str = DEFAULT_MODEL_NAME,
) -> dict[str, Any]:
    """Live-demo callable discovered by :mod:`agentsec.demo`.

    When ``corpus_dir`` (or ``AGENTSEC_CORPUS_DIR``) is set, its manifest is
    verified before use.  Otherwise the source development scenario is used and
    the returned record marks that fact; source scenarios are never formal data.
    """

    resolved_corpus = corpus_dir or os.environ.get("AGENTSEC_CORPUS_DIR")
    if resolved_corpus:
        from .redteam import load_frozen_scenarios

        scenarios = {item.scenario_id: item for item in load_frozen_scenarios(resolved_corpus)}
        payload_base_dir: str | Path | None = resolved_corpus
        input_kind = "verified_frozen_corpus"
    else:
        scenarios = {item.scenario_id: item for item in load_scenarios()}
        payload_base_dir = None
        input_kind = "source_development_scenario"
    if scenario_id not in scenarios:
        raise ValueError(f"unknown scenario {scenario_id!r}")
    model_config = {
        "base_url": base_url,
        "model": model_name,
        "temperature": 0.7,
        "top_p": 0.8,
        "stream": False,
        "demo": True,
    }
    from .schemas import stable_model_hash

    run_spec = RunSpec(
        scenario_id=scenario_id,
        content_condition=ContentCondition(condition),
        defense_arm=DefenseArm(defense),
        seed=int(seed),
        repetition=0,
        model_config_hash=stable_model_hash(model_config),
    )
    output_root = Path(artifact_root) if artifact_root else PROJECT_ROOT / "artifacts" / "demo"
    attempt_id = f"attempt-{uuid.uuid4().hex[:12]}"
    with OpenAIModelClient(base_url=base_url, model=model_name) as client:
        outcome = ExperimentOrchestrator(
            client,
            artifact_root=output_root,
            temperature=0.7,
            top_p=0.8,
        ).run_attempt(
            scenarios[scenario_id],
            run_spec,
            payload_base_dir=payload_base_dir,
            attempt_id=attempt_id,
        )
    attempt_dir = output_root / run_spec.run_id / attempt_id
    return {
        "input_kind": input_kind,
        "artifact_directory": str(attempt_dir.resolve()),
        "outcome": outcome.model_dump(mode="json"),
    }


def load_record(path: str | Path) -> dict[str, Any]:
    """Load a flat experiment record from a file or attempt directory."""

    candidate = Path(path)
    if candidate.is_dir():
        candidate = candidate / "record.json"
    data = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("experiment record must be a JSON object")
    return dict(data)


__all__ = [
    "PlanExecutionSummary",
    "execute_run_plan",
    "load_record",
    "load_verified_formal_inputs",
    "run_demo_case",
]
