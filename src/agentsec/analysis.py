"""Auditable loading and publication-oriented analysis of run artifacts."""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .aggregate import PairedComparison, paired_comparison, summarize_binary_metric
from .schemas import ContentCondition, DefenseArm, RunResult, RunSpec


ANALYSIS_METRICS = (
    "exposure",
    "attempted_attack",
    "blocked_attack",
    "executed_unauthorized_effect",
    "secret_leakage",
    "benign_task_success",
    "benign_block",
)
CONDITION_ORDER = {item.value: index for index, item in enumerate(ContentCondition)}
DEFENSE_ORDER = {item.value: index for index, item in enumerate(DefenseArm)}
DEFENSE_LABELS = {
    "allow_all": "Allow all",
    "prompt_only": "Prompt only",
    "capability_only": "Capability",
    "provenance_only": "Provenance-only",
    "prompt_provenance_only": "Prompt + provenance",
    "capability_provenance_only": "Capability + provenance",
    "prompt_capability_only": "Prompt + capability",
    "full": "Full",
    "pact_l2": "PACT-L2 (experimental)",
}
# Keep historical publication figures byte-layout compatible. Experimental
# arms remain available to loaders and summary tables but require a separate
# explicitly labelled figure rather than silently changing published plots.
PUBLICATION_DEFENSES = tuple(
    defense for defense in DEFENSE_LABELS if defense != DefenseArm.PACT_L2.value
)
EXPECTED_ARTIFACT_FILES = {
    "run_spec": "run_spec.json",
    "world_before": "world_before.json",
    "world_after": "world_after.json",
    "audit": "audit.jsonl",
    "final_response": "final_response.json",
    "result": "result.json",
    "record": "record.json",
}


class ArtifactAnalysisError(ValueError):
    """The selected artifact set is incomplete, inconsistent, or ambiguous."""


class LoadedRecord(BaseModel):
    """One validated flat record and its move-safe source identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_spec: RunSpec
    result: RunResult
    attempt_id: str
    record_path: str
    record_sha256: str

    @field_validator("attempt_id")
    @classmethod
    def valid_attempt_id(cls, value: str) -> str:
        path = Path(value)
        if not value or path.is_absolute() or len(path.parts) != 1 or value in {".", ".."}:
            raise ValueError("attempt_id must be one non-empty path component")
        return value

    @field_validator("record_path")
    @classmethod
    def relative_record_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("record_path must be relative and cannot contain '..'")
        return value


class AnalysisReport(BaseModel):
    """Small machine-readable summary returned after writing derived outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_count: int = Field(ge=0)
    valid_count: int = Field(ge=0)
    invalid_count: int = Field(ge=0)
    input_digest: str
    comparison_count: int = Field(ge=0)
    output_files: tuple[str, ...]


def load_artifact_records(
    root: str | Path | Sequence[str | Path],
    *,
    expected_run_specs: Sequence[RunSpec] | None = None,
) -> tuple[LoadedRecord, ...]:
    """Recursively load complete ``record.json`` files without choosing retries.

    Any repeated ``run_id`` is rejected, including two append-only attempts for
    the same planned run.  Analysis must therefore be given an unambiguous ITT
    attempt set rather than silently preferring a successful or later retry.
    """

    roots = (root,) if isinstance(root, (str, Path)) else tuple(root)
    if not roots:
        raise ArtifactAnalysisError("at least one artifact root is required")

    records: list[LoadedRecord] = []
    for root_index, artifact_root in enumerate(roots):
        selected = Path(artifact_root).expanduser().resolve()
        if not selected.exists():
            raise ArtifactAnalysisError(f"artifact path does not exist: {selected}")
        if selected.is_file():
            paths = [selected]
            base = selected.parent
        else:
            paths = sorted(path.resolve() for path in selected.rglob("record.json"))
            base = selected
        if not paths:
            raise ArtifactAnalysisError(
                f"no record.json artifacts found under: {selected}"
            )
        for path in paths:
            try:
                path.relative_to(base)
            except ValueError as exc:
                raise ArtifactAnalysisError(
                    f"record.json symlink escapes the selected artifact root: {path}"
                ) from exc

        loaded = [_load_record(path, base=base) for path in paths]
        if len(roots) > 1:
            loaded = [
                record.model_copy(
                    update={
                        "record_path": (
                            f"root-{root_index + 1:04d}/{record.record_path}"
                        )
                    }
                )
                for record in loaded
            ]
        records.extend(loaded)

    by_run_id: dict[str, list[LoadedRecord]] = {}
    for record in records:
        by_run_id.setdefault(record.run_spec.run_id, []).append(record)
    ambiguous = {run_id: rows for run_id, rows in by_run_id.items() if len(rows) > 1}
    if ambiguous:
        details = "; ".join(
            f"{run_id}: " + ", ".join(row.record_path for row in rows)
            for run_id, rows in sorted(ambiguous.items())
        )
        raise ArtifactAnalysisError(
            "duplicate run IDs create attempt ambiguity; select exactly one "
            f"pre-declared attempt per run ({details})"
        )

    ordered = tuple(sorted(records, key=_record_sort_key))
    if expected_run_specs is not None:
        validate_records_against_plan(ordered, expected_run_specs)
    return ordered


def validate_records_against_plan(
    records: Sequence[LoadedRecord], expected_run_specs: Sequence[RunSpec]
) -> None:
    """Require an exact, configuration-identical result for every planned run."""

    expected: dict[str, RunSpec] = {}
    for run_spec in expected_run_specs:
        if run_spec.run_id in expected:
            raise ArtifactAnalysisError(
                f"expected plan contains duplicate run ID {run_spec.run_id!r}"
            )
        expected[run_spec.run_id] = run_spec
    observed = {record.run_spec.run_id: record for record in records}
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    drifted = sorted(
        run_id
        for run_id in set(expected) & set(observed)
        if observed[run_id].run_spec != expected[run_id]
    )
    if missing or unexpected or drifted:
        raise ArtifactAnalysisError(
            "artifact set does not exactly match the verified run plan "
            f"(missing={len(missing)}, unexpected={len(unexpected)}, "
            f"drifted={len(drifted)})"
        )


def registered_comparisons(
    records: Sequence[LoadedRecord | Mapping[str, Any]],
    *,
    confidence: float = 0.95,
    bootstrap_seed: int = 4313,
    bootstrap_resamples: int = 10_000,
) -> tuple[PairedComparison, ...]:
    """Return all pre-declared contrasts, including the two task families."""

    rows = list(records)
    families: tuple[tuple[str, set[str]], ...] = (
        ("all", {"T1", "T2", "T3", "T4", "T5", "T6"}),
        ("capability_t1_t4", {"T1", "T2", "T3", "T4"}),
        ("provenance_t5_t6", {"T5", "T6"}),
    )
    comparisons: list[PairedComparison] = []
    for family_name, scenario_ids in families:
        family_rows = [row for row in rows if _value(row, "scenario_id") in scenario_ids]
        comparisons.extend(
            (
                paired_comparison(
                    family_rows,
                    name=f"h1_attack_minus_placebo_allow_all__{family_name}",
                    metric="executed_unauthorized_effect",
                    left_selector={"content_condition": "attack", "defense_arm": "allow_all"},
                    right_selector={"content_condition": "placebo", "defense_arm": "allow_all"},
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
                paired_comparison(
                    family_rows,
                    name=f"h2_full_minus_allow_all_attack_executed__{family_name}",
                    metric="executed_unauthorized_effect",
                    left_selector={"content_condition": "attack", "defense_arm": "full"},
                    right_selector={"content_condition": "attack", "defense_arm": "allow_all"},
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
                paired_comparison(
                    family_rows,
                    name=f"h2_full_minus_allow_all_attack_leakage__{family_name}",
                    metric="secret_leakage",
                    left_selector={"content_condition": "attack", "defense_arm": "full"},
                    right_selector={"content_condition": "attack", "defense_arm": "allow_all"},
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
                paired_comparison(
                    family_rows,
                    name=f"h4_full_minus_allow_all_clean_utility__{family_name}",
                    metric="benign_task_success",
                    left_selector={"content_condition": "clean", "defense_arm": "full"},
                    right_selector={"content_condition": "clean", "defense_arm": "allow_all"},
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
            )
        )
    provenance_rows = [row for row in rows if _value(row, "scenario_id") in {"T5", "T6"}]
    comparisons.append(
        paired_comparison(
            provenance_rows,
            name="h3_full_minus_capability_only_attack_leakage__provenance_t5_t6",
            metric="secret_leakage",
            left_selector={"content_condition": "attack", "defense_arm": "full"},
            right_selector={"content_condition": "attack", "defense_arm": "capability_only"},
            confidence=confidence,
            bootstrap_seed=bootstrap_seed,
            bootstrap_resamples=bootstrap_resamples,
        )
    )
    if any(
        _value(row, "defense_arm") == "prompt_capability_only" for row in rows
    ):
        comparisons.extend(
            (
                paired_comparison(
                    provenance_rows,
                    name=(
                        "a1_prompt_capability_minus_capability_attack_leakage"
                        "__provenance_t5_t6"
                    ),
                    metric="secret_leakage",
                    left_selector={
                        "content_condition": "attack",
                        "defense_arm": "prompt_capability_only",
                    },
                    right_selector={
                        "content_condition": "attack",
                        "defense_arm": "capability_only",
                    },
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
                paired_comparison(
                    provenance_rows,
                    name=(
                        "a2_full_minus_prompt_capability_attack_leakage"
                        "__provenance_t5_t6"
                    ),
                    metric="secret_leakage",
                    left_selector={
                        "content_condition": "attack",
                        "defense_arm": "full",
                    },
                    right_selector={
                        "content_condition": "attack",
                        "defense_arm": "prompt_capability_only",
                    },
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
            )
        )
    if any(
        _value(row, "defense_arm") == "capability_provenance_only" for row in rows
    ):
        comparisons.extend(
            (
                paired_comparison(
                    provenance_rows,
                    name=(
                        "a3_capability_provenance_minus_capability_attack_leakage"
                        "__provenance_t5_t6"
                    ),
                    metric="secret_leakage",
                    left_selector={
                        "content_condition": "attack",
                        "defense_arm": "capability_provenance_only",
                    },
                    right_selector={
                        "content_condition": "attack",
                        "defense_arm": "capability_only",
                    },
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
                paired_comparison(
                    provenance_rows,
                    name=(
                        "a4_full_minus_capability_provenance_attack_leakage"
                        "__provenance_t5_t6"
                    ),
                    metric="secret_leakage",
                    left_selector={
                        "content_condition": "attack",
                        "defense_arm": "full",
                    },
                    right_selector={
                        "content_condition": "attack",
                        "defense_arm": "capability_provenance_only",
                    },
                    confidence=confidence,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_resamples=bootstrap_resamples,
                ),
            )
        )
    present_arms = {_value(row, "defense_arm") for row in rows}
    if {"allow_all", "provenance_only"}.issubset(present_arms):
        comparisons.append(
            paired_comparison(
                provenance_rows,
                name=(
                    "a5_provenance_only_minus_allow_all_attack_leakage"
                    "__provenance_t5_t6"
                ),
                metric="secret_leakage",
                left_selector={
                    "content_condition": "attack",
                    "defense_arm": "provenance_only",
                },
                right_selector={
                    "content_condition": "attack",
                    "defense_arm": "allow_all",
                },
                confidence=confidence,
                bootstrap_seed=bootstrap_seed,
                bootstrap_resamples=bootstrap_resamples,
            )
        )
    if {"prompt_only", "prompt_provenance_only"}.issubset(present_arms):
        comparisons.append(
            paired_comparison(
                provenance_rows,
                name=(
                    "a6_prompt_provenance_minus_prompt_only_attack_leakage"
                    "__provenance_t5_t6"
                ),
                metric="secret_leakage",
                left_selector={
                    "content_condition": "attack",
                    "defense_arm": "prompt_provenance_only",
                },
                right_selector={
                    "content_condition": "attack",
                    "defense_arm": "prompt_only",
                },
                confidence=confidence,
                bootstrap_seed=bootstrap_seed,
                bootstrap_resamples=bootstrap_resamples,
            )
        )
    if {"full", "prompt_provenance_only"}.issubset(present_arms):
        comparisons.append(
            paired_comparison(
                provenance_rows,
                name=(
                    "a7_full_minus_prompt_provenance_attack_leakage"
                    "__provenance_t5_t6"
                ),
                metric="secret_leakage",
                left_selector={
                    "content_condition": "attack",
                    "defense_arm": "full",
                },
                right_selector={
                    "content_condition": "attack",
                    "defense_arm": "prompt_provenance_only",
                },
                confidence=confidence,
                bootstrap_seed=bootstrap_seed,
                bootstrap_resamples=bootstrap_resamples,
            )
        )
    if {"full", "provenance_only"}.issubset(present_arms):
        comparisons.append(
            paired_comparison(
                provenance_rows,
                name=(
                    "a8_full_minus_provenance_only_attack_leakage"
                    "__provenance_t5_t6"
                ),
                metric="secret_leakage",
                left_selector={
                    "content_condition": "attack",
                    "defense_arm": "full",
                },
                right_selector={
                    "content_condition": "attack",
                    "defense_arm": "provenance_only",
                },
                confidence=confidence,
                bootstrap_seed=bootstrap_seed,
                bootstrap_resamples=bootstrap_resamples,
            )
        )
    return tuple(comparisons)


def analyze_artifacts(
    artifact_root: str | Path | Sequence[str | Path],
    output_dir: str | Path,
    *,
    expected_run_specs: Sequence[RunSpec] | None = None,
    generate_plots: bool = True,
    bootstrap_seed: int = 4313,
    bootstrap_resamples: int = 10_000,
) -> AnalysisReport:
    """Validate raw artifacts and create a new, self-contained result bundle."""

    records = load_artifact_records(
        artifact_root, expected_run_specs=expected_run_specs
    )
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)

    flat_records = [_flat_record(record) for record in records]
    cell_rows = _summary_rows(
        records,
        group_by=("scenario_id", "content_condition", "defense_arm"),
    )
    arm_rows = _summary_rows(records, group_by=("content_condition", "defense_arm"))
    comparisons = registered_comparisons(
        records,
        bootstrap_seed=bootstrap_seed,
        bootstrap_resamples=bootstrap_resamples,
    )
    comparison_rows = [_flatten_comparison(item) for item in comparisons]
    publication_rows = _publication_table_rows(records)

    _write_json(output / "records.json", flat_records)
    _write_csv(output / "records.csv", flat_records)
    _write_json(output / "cell_summary.json", cell_rows)
    _write_csv(output / "cell_summary.csv", cell_rows)
    _write_json(output / "arm_summary.json", arm_rows)
    _write_csv(output / "arm_summary.csv", arm_rows)
    _write_json(
        output / "registered_comparisons.json",
        [item.model_dump(mode="json") for item in comparisons],
    )
    _write_csv(output / "registered_comparisons.csv", comparison_rows)
    _write_csv(output / "publication_table.csv", publication_rows)
    (output / "publication_table.tex").write_text(
        _publication_latex(publication_rows), encoding="utf-8"
    )
    if generate_plots:
        _write_publication_plots(records, output)

    input_hashes = {record.record_path: record.record_sha256 for record in records}
    input_digest = hashlib.sha256(
        json.dumps(input_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    summary = {
        "record_count": len(records),
        "valid_count": sum(record.result.valid for record in records),
        "invalid_count": sum(not record.result.valid for record in records),
        "input_digest": input_digest,
        "bootstrap_seed": bootstrap_seed,
        "bootstrap_resamples": bootstrap_resamples,
        "analysis_metrics": list(ANALYSIS_METRICS),
        "comparison_count": len(comparisons),
    }
    _write_json(output / "results_summary.json", summary)

    output_hashes = {
        path.relative_to(output).as_posix(): _sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    manifest = {
        "schema_version": "1",
        "input_records_sha256": input_hashes,
        "input_digest": input_digest,
        "outputs_sha256": output_hashes,
        **summary,
    }
    _write_json(output / "analysis_manifest.json", manifest)
    output_files = tuple(
        path.relative_to(output).as_posix()
        for path in sorted(output.rglob("*"))
        if path.is_file()
    )
    return AnalysisReport(
        record_count=len(records),
        valid_count=summary["valid_count"],
        invalid_count=summary["invalid_count"],
        input_digest=input_digest,
        comparison_count=len(comparisons),
        output_files=output_files,
    )


def _load_record(path: Path, *, base: Path) -> LoadedRecord:
    try:
        encoded = path.read_bytes()
        raw = json.loads(encoded)
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactAnalysisError(f"cannot parse record artifact {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ArtifactAnalysisError(f"record artifact is not a JSON object: {path}")

    run_fields = set(RunSpec.model_fields)
    result_fields = set(RunResult.model_fields)
    required = run_fields | result_fields | {"attempt_id"}
    missing = sorted(required - set(raw))
    unknown = sorted(set(raw) - required)
    if missing or unknown:
        raise ArtifactAnalysisError(
            f"incomplete or unknown fields in {path} "
            f"(missing={missing}, unknown={unknown})"
        )

    supplied_run_id = raw.get("run_id")
    if not isinstance(supplied_run_id, str) or not supplied_run_id:
        raise ArtifactAnalysisError(f"record has no non-empty run_id: {path}")
    derived_data = {field: raw[field] for field in run_fields if field != "run_id"}
    try:
        derived = RunSpec.model_validate(derived_data)
        run_spec = RunSpec.model_validate({field: raw[field] for field in run_fields})
        result = RunResult.model_validate({field: raw[field] for field in result_fields})
    except Exception as exc:
        raise ArtifactAnalysisError(f"record schema validation failed: {path}") from exc
    if derived.run_id != supplied_run_id:
        raise ArtifactAnalysisError(
            f"record run_id is not reproducible from its RunSpec: {path}"
        )
    if result.run_id != run_spec.run_id:
        raise ArtifactAnalysisError(f"RunSpec and RunResult run_id differ: {path}")
    relative = path.relative_to(base).as_posix()
    try:
        loaded = LoadedRecord(
            run_spec=run_spec,
            result=result,
            attempt_id=raw["attempt_id"],
            record_path=relative,
            record_sha256=hashlib.sha256(encoded).hexdigest(),
        )
    except Exception as exc:
        raise ArtifactAnalysisError(f"record metadata validation failed: {path}") from exc
    expected_paths = {
        label: (
            Path(loaded.run_spec.run_id) / loaded.attempt_id / filename
        ).as_posix()
        for label, filename in EXPECTED_ARTIFACT_FILES.items()
    }
    if loaded.result.artifact_paths != expected_paths:
        raise ArtifactAnalysisError(
            f"record does not contain the complete canonical artifact-path map: {path}"
        )
    return loaded


def _flat_record(record: LoadedRecord) -> dict[str, Any]:
    row = {
        **record.run_spec.model_dump(mode="json"),
        **record.result.model_dump(mode="json", exclude={"usage", "artifact_paths"}),
        **{
            f"usage_{name}": value
            for name, value in record.result.usage.model_dump(mode="json").items()
        },
        "artifact_paths_json": json.dumps(
            record.result.artifact_paths,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        "attempt_id": record.attempt_id,
        "record_path": record.record_path,
        "record_sha256": record.record_sha256,
    }
    return row


def _summary_rows(
    records: Sequence[LoadedRecord], *, group_by: Sequence[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for metric in ANALYSIS_METRICS:
        for summary in summarize_binary_metric(records, metric, group_by=group_by):
            rows.append(
                {
                    **summary.group,
                    "metric": metric,
                    "planned_n": summary.planned_n,
                    "valid_n": summary.valid_n,
                    "invalid_n": summary.invalid_n,
                    "successes": summary.successes,
                    "valid_successes": summary.valid_successes,
                    "invalid_successes": summary.invalid_successes,
                    "itt_rate": summary.itt_rate,
                    "itt_lower_bound_rate": summary.itt_lower_bound_rate,
                    "itt_upper_bound_rate": summary.itt_upper_bound_rate,
                    "itt_ci_lower": summary.itt_wilson.lower if summary.itt_wilson else None,
                    "itt_ci_upper": summary.itt_wilson.upper if summary.itt_wilson else None,
                    "valid_only_rate": summary.valid_only_rate,
                    "valid_ci_lower": (
                        summary.valid_only_wilson.lower
                        if summary.valid_only_wilson
                        else None
                    ),
                    "valid_ci_upper": (
                        summary.valid_only_wilson.upper
                        if summary.valid_only_wilson
                        else None
                    ),
                }
            )
    return rows


def _flatten_comparison(comparison: PairedComparison) -> dict[str, Any]:
    row = comparison.model_dump(mode="json", exclude={"left_selector", "right_selector"})
    row["left_selector_json"] = json.dumps(
        comparison.left_selector, sort_keys=True, separators=(",", ":")
    )
    row["right_selector_json"] = json.dumps(
        comparison.right_selector, sort_keys=True, separators=(",", ":")
    )
    for field in (
        "left_wilson",
        "right_wilson",
        "valid_left_wilson",
        "valid_right_wilson",
    ):
        value = row.pop(field)
        row[f"{field}_lower"] = value["lower"] if value else None
        row[f"{field}_upper"] = value["upper"] if value else None
    for field in ("risk_difference_ci", "valid_risk_difference_ci"):
        value = row.pop(field)
        row[f"{field}_lower"] = value[0] if value else None
        row[f"{field}_upper"] = value[1] if value else None
    return row


def _publication_table_rows(records: Sequence[LoadedRecord]) -> list[dict[str, Any]]:
    families: tuple[tuple[str, set[str]], ...] = (
        ("All tasks", {"T1", "T2", "T3", "T4", "T5", "T6"}),
        ("T1--T4 capability", {"T1", "T2", "T3", "T4"}),
        ("T5--T6 provenance", {"T5", "T6"}),
    )
    rows: list[dict[str, Any]] = []
    for family, ids in families:
        for condition in ("attack", "clean"):
            for defense in DEFENSE_ORDER:
                subset = [
                    record
                    for record in records
                    if record.run_spec.scenario_id in ids
                    and record.run_spec.content_condition.value == condition
                    and record.run_spec.defense_arm.value == defense
                ]
                valid = [record for record in subset if record.result.valid]
                row: dict[str, Any] = {
                    "family": family,
                    "condition": condition,
                    "defense": defense,
                    "planned_n": len(subset),
                    "valid_n": len(valid),
                    "invalid_n": len(subset) - len(valid),
                }
                for metric in (
                    "executed_unauthorized_effect",
                    "secret_leakage",
                    "benign_task_success",
                    "benign_block",
                ):
                    count = sum(bool(getattr(record.result, metric)) for record in valid)
                    from .aggregate import wilson_interval

                    interval = wilson_interval(count, len(valid))
                    row[f"{metric}_rate"] = count / len(valid) if valid else None
                    row[f"{metric}_ci_lower"] = interval.lower if interval else None
                    row[f"{metric}_ci_upper"] = interval.upper if interval else None
                rows.append(row)
    return rows


def _publication_latex(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "% Auto-generated by agentsec.analysis; do not edit by hand.",
        "\\begin{tabular}{lllrrrr}",
        "\\toprule",
        "Family & Condition & Defense & Valid/Planned & Executed & Leakage & Utility \\\\",
        "\\midrule",
    ]
    for row in rows:
        lines.append(
            f"{_latex_escape(str(row['family']))} & "
            f"{_latex_escape(str(row['condition']))} & "
            f"{_latex_escape(str(row['defense']))} & "
            f"{row['valid_n']}/{row['planned_n']} & "
            f"{_format_rate_ci(row, 'executed_unauthorized_effect')} & "
            f"{_format_rate_ci(row, 'secret_leakage')} & "
            f"{_format_rate_ci(row, 'benign_task_success')} \\\\"
        )
    lines.extend(("\\bottomrule", "\\end{tabular}", ""))
    return "\n".join(lines)


def _write_publication_plots(records: Sequence[LoadedRecord], output: Path) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError(
            "publication plots require the optional analysis dependency matplotlib"
        ) from exc

    defenses = list(PUBLICATION_DEFENSES)
    labels = [DEFENSE_LABELS[defense] for defense in defenses]

    def rates(
        condition: str, metric: str, ids: set[str] | None = None
    ) -> tuple[list[float], list[float], list[float]]:
        values: list[float] = []
        lower_errors: list[float] = []
        upper_errors: list[float] = []
        from .aggregate import wilson_interval

        for defense in defenses:
            subset = [
                record
                for record in records
                if record.result.valid
                and record.run_spec.content_condition.value == condition
                and record.run_spec.defense_arm.value == defense
                and (ids is None or record.run_spec.scenario_id in ids)
            ]
            successes = sum(bool(getattr(record.result, metric)) for record in subset)
            rate = successes / len(subset) if subset else 0.0
            interval = wilson_interval(successes, len(subset))
            values.append(rate)
            # Floating-point rounding can make an endpoint differ from a
            # boundary rate by a tiny negative epsilon (e.g. p=1 and upper
            # clipped to 0.9999999999999999).  Matplotlib requires nonnegative
            # error bars, so clamp the derived distances without changing the
            # reported rate or interval in the publication tables.
            lower_errors.append(
                max(0.0, rate - interval.lower) if interval else 0.0
            )
            upper_errors.append(
                max(0.0, interval.upper - rate) if interval else 0.0
            )
        return values, lower_errors, upper_errors

    x = list(range(len(defenses)))
    width = 0.36
    figure, axis = plt.subplots(figsize=(7.2, 4.2))
    executed, executed_lower, executed_upper = rates(
        "attack", "executed_unauthorized_effect"
    )
    leakage, leakage_lower, leakage_upper = rates("attack", "secret_leakage")
    axis.bar(
        [value - width / 2 for value in x],
        executed,
        width,
        yerr=[executed_lower, executed_upper],
        label="Executed unsafe effect",
        capsize=3,
    )
    axis.bar(
        [value + width / 2 for value in x],
        leakage,
        width,
        yerr=[leakage_lower, leakage_upper],
        label="Exact secret leakage",
        capsize=3,
    )
    _style_axis(axis, x, labels, "Attack-condition rate")
    axis.legend(frameon=False)
    figure.tight_layout()
    figure.savefig(output / "security_outcomes.png", dpi=220, bbox_inches="tight")
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(7.2, 4.2))
    utility, utility_lower, utility_upper = rates("clean", "benign_task_success")
    false_block, false_block_lower, false_block_upper = rates(
        "clean", "benign_block"
    )
    axis.bar(
        [value - width / 2 for value in x],
        utility,
        width,
        yerr=[utility_lower, utility_upper],
        label="Benign task success",
        capsize=3,
    )
    axis.bar(
        [value + width / 2 for value in x],
        false_block,
        width,
        yerr=[false_block_lower, false_block_upper],
        label="Benign block",
        capsize=3,
    )
    _style_axis(axis, x, labels, "Clean-condition rate")
    axis.legend(frameon=False)
    figure.tight_layout()
    figure.savefig(output / "utility_outcomes.png", dpi=220, bbox_inches="tight")
    plt.close(figure)

    figure, axes = plt.subplots(1, 2, figsize=(10.5, 4.0), sharey=True)
    for axis, title, ids in (
        (axes[0], "T1--T4 capability tasks", {"T1", "T2", "T3", "T4"}),
        (axes[1], "T5--T6 provenance tasks", {"T5", "T6"}),
    ):
        values, lower_errors, upper_errors = rates(
            "attack", "executed_unauthorized_effect", ids
        )
        axis.bar(
            x,
            values,
            yerr=[lower_errors, upper_errors],
            color="#4C78A8",
            capsize=3,
        )
        _style_axis(axis, x, labels, "Executed unsafe-effect rate")
        axis.set_title(title)
    figure.tight_layout()
    figure.savefig(output / "task_family_outcomes.png", dpi=220, bbox_inches="tight")
    plt.close(figure)


def _style_axis(axis: Any, x: Sequence[int], labels: Sequence[str], ylabel: str) -> None:
    axis.set_xticks(x, labels, rotation=18, ha="right")
    axis.set_ylim(0.0, 1.05)
    axis.set_ylabel(ylabel)
    axis.grid(axis="y", alpha=0.25)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    fieldnames = list(rows[0]) if rows else []
    with path.open("x", encoding="utf-8", newline="") as handle:
        if not fieldnames:
            return
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def _record_sort_key(record: LoadedRecord) -> tuple[Any, ...]:
    run_spec = record.run_spec
    return (
        run_spec.scenario_id,
        CONDITION_ORDER[run_spec.content_condition.value],
        DEFENSE_ORDER[run_spec.defense_arm.value],
        run_spec.repetition,
        run_spec.seed,
        run_spec.run_id,
    )


def _value(record: Any, field: str) -> Any:
    if isinstance(record, Mapping):
        if field in record:
            value = record[field]
        else:
            for nested in (record.get("run_spec"), record.get("result")):
                if nested is not None:
                    try:
                        return _value(nested, field)
                    except KeyError:
                        pass
            raise KeyError(field)
    elif hasattr(record, field):
        value = getattr(record, field)
    else:
        for nested_name in ("run_spec", "result"):
            nested = getattr(record, nested_name, None)
            if nested is not None:
                try:
                    return _value(nested, field)
                except KeyError:
                    pass
        raise KeyError(field)
    return getattr(value, "value", value)


def _format_rate_ci(row: Mapping[str, Any], metric: str) -> str:
    rate = row[f"{metric}_rate"]
    lower = row[f"{metric}_ci_lower"]
    upper = row[f"{metric}_ci_upper"]
    if rate is None or lower is None or upper is None:
        return "--"
    return (
        f"{100.0 * float(rate):.1f}\\% "
        f"[{100.0 * float(lower):.1f}, {100.0 * float(upper):.1f}]"
    )


def _latex_escape(value: str) -> str:
    return value.replace("_", "\\_").replace("%", "\\%")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "ANALYSIS_METRICS",
    "DEFENSE_LABELS",
    "AnalysisReport",
    "ArtifactAnalysisError",
    "LoadedRecord",
    "analyze_artifacts",
    "load_artifact_records",
    "registered_comparisons",
    "validate_records_against_plan",
]
