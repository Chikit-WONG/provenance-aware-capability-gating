"""Analysis and publication helpers for the native AgentDojo slice.

This module intentionally keeps native AgentDojo outcomes separate from the
project-harness aggregates.  It accepts the small project-owned contracts in
:mod:`agentsec.agentdojo_external`, validates exact formal-plan coverage and
attempt selection, and produces deterministic publication-friendly summaries.

The analysis uses intention-to-test (ITT) denominators.  An invalid selected
record is conservatively projected to utility failure and targeted attack
success (for attacked rows), while a second valid-only view is reported beside
it.  The official AgentDojo security value is used as-is; it is never inverted.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
import zlib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .agentdojo_external import (
    AGENTDOJO_SUITES,
    AgentDojoResultRecord,
    AgentDojoRunSpec,
    TRANSFER_DEFENSES,
)
from .aggregate import wilson_interval
from .attempts import AttemptSelectionManifest, INFRASTRUCTURE_REASONS

_ATTACKS = ("important_instructions", "tool_knowledge")
# Keep one analyzer for both the two-arm external baseline and the seven-arm
# capability/provenance transfer matrix.  Baseline inputs simply omit the
# additional arms, so their published rows remain unchanged.
_DEFENSES = TRANSFER_DEFENSES
_HEX64 = set("0123456789abcdef")


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_plan(rows: Sequence[AgentDojoRunSpec | Mapping[str, Any]]) -> list[AgentDojoRunSpec]:
    return [row if isinstance(row, AgentDojoRunSpec) else AgentDojoRunSpec.model_validate(row) for row in rows]


def _normalise_manifest(manifest: AttemptSelectionManifest | Mapping[str, Any]) -> AttemptSelectionManifest:
    return manifest if isinstance(manifest, AttemptSelectionManifest) else AttemptSelectionManifest.model_validate(manifest)


def _plan_index(rows: Sequence[AgentDojoRunSpec]) -> dict[str, AgentDojoRunSpec]:
    index: dict[str, AgentDojoRunSpec] = {}
    for row in rows:
        if row.run_id in index:
            raise ValueError(f"duplicate run ID in frozen plan: {row.run_id}")
        index[row.run_id] = row
    return index


def validate_formal_records(
    records: Iterable[AgentDojoResultRecord | Mapping[str, Any]],
    plan_rows: Sequence[AgentDojoRunSpec | Mapping[str, Any]],
    selection_manifest: AttemptSelectionManifest | Mapping[str, Any],
    plan_hash: str,
    record_hashes: Mapping[str, str] | None = None,
) -> list[AgentDojoResultRecord]:
    """Validate exact formal coverage and selected-attempt identity.

    ``records`` must contain exactly one selected record for each formal plan
    row.  Development rows, extra/duplicate run IDs, hash-drifted plan
    manifests, and unselected/ambiguous attempts are rejected.  This function
    deliberately does not recompute record-file hashes: callers that have
    files should verify those bytes while loading them, then pass the parsed
    records here.
    """

    rows = _normalise_plan(plan_rows)
    if not rows:
        raise ValueError("formal plan is empty")
    if any(row.phase != "formal" for row in rows):
        raise ValueError("formal analysis plan contains development rows")
    expected = _plan_index(rows)
    manifest = _normalise_manifest(selection_manifest)
    if not isinstance(plan_hash, str) or len(plan_hash) != 64 or set(plan_hash) - _HEX64:
        raise ValueError("plan_sha256 must be a lowercase SHA-256 hex digest")
    if manifest.plan_sha256 != plan_hash:
        raise ValueError("attempt-selection plan_sha256 does not match frozen plan")
    selections = {selection.run_id: selection for selection in manifest.rows}
    if len(selections) != len(manifest.rows):
        raise ValueError("attempt-selection manifest contains duplicate run IDs")
    missing_selection = sorted(set(expected) - set(selections))
    extra_selection = sorted(set(selections) - set(expected))
    if missing_selection:
        raise ValueError(f"attempt-selection manifest missing run IDs: {missing_selection!r}")
    if extra_selection:
        raise ValueError(f"attempt-selection manifest has extra run IDs: {extra_selection!r}")

    parsed: list[AgentDojoResultRecord] = []
    seen: set[str] = set()
    for item in records:
        record = item if isinstance(item, AgentDojoResultRecord) else AgentDojoResultRecord.model_validate(item)
        if record.phase != "formal":
            raise ValueError(f"development record is not allowed in formal analysis: {record.run_id}")
        if record.run_id in seen:
            raise ValueError(f"duplicate formal record run ID: {record.run_id}")
        seen.add(record.run_id)
        row = expected.get(record.run_id)
        if row is None:
            raise ValueError(f"unexpected/extra formal record run ID: {record.run_id}")
        if record.run_spec != row:
            raise ValueError(f"record run spec does not match frozen plan row {record.run_id}")
        selection = selections[record.run_id]
        if selection.selected_attempt is None:
            raise ValueError(f"run {record.run_id} has no unambiguous selected attempt")
        if record.attempt_id != selection.selected_attempt:
            raise ValueError(
                f"record attempt {record.attempt_id} is not selected attempt "
                f"{selection.selected_attempt} for {record.run_id}"
            )
        if record_hashes is not None:
            actual_hash = record_hashes.get(record.run_id)
            if actual_hash != selection.selected_record_sha256:
                raise ValueError(f"selected record hash mismatch for {record.run_id}")
        parsed.append(record)
    missing = sorted(set(expected) - seen)
    if missing:
        raise ValueError(f"formal records missing run IDs: {missing!r}")
    if len(parsed) != len(rows):
        raise ValueError("formal record count does not match frozen plan")
    return parsed


def _metric_summary(
    rows: Sequence[AgentDojoResultRecord],
    metric: str,
    *,
    conservative_invalid: bool,
) -> dict[str, Any]:
    planned_n = len(rows)
    valid_rows = [row for row in rows if row.valid]
    valid_n = len(valid_rows)
    invalid_n = planned_n - valid_n
    successes = 0
    valid_successes = 0
    for row in rows:
        value = _field(row, metric)
        if row.valid:
            success = bool(value)
            valid_successes += int(success)
        elif conservative_invalid and row.invalid_reason in INFRASTRUCTURE_REASONS:
            success = True if metric == "targeted_attack_success" else False
        else:
            # Behavioral invalids retain their observed metric semantics; they
            # are not silently converted into infrastructure failures.
            success = bool(value)
        successes += int(success)
    interval = wilson_interval(successes, planned_n)
    valid_interval = wilson_interval(valid_successes, valid_n)
    return {
        "metric": metric,
        "planned_n": planned_n,
        "valid_n": valid_n,
        "invalid_n": invalid_n,
        "successes": successes,
        "valid_successes": valid_successes,
        "itt_rate": successes / planned_n if planned_n else None,
        "valid_only_rate": valid_successes / valid_n if valid_n else None,
        "wilson": interval.model_dump(mode="json") if interval is not None else None,
        "valid_only_wilson": valid_interval.model_dump(mode="json") if valid_interval is not None else None,
    }


def _attack_summary_rows(
    grouped: Mapping[tuple[str, str, str], Sequence[AgentDojoResultRecord]],
    *,
    include_suite: bool,
) -> list[dict[str, Any]]:
    """Build deterministic attack rows from a suite-aware grouping."""

    rows: list[dict[str, Any]] = []
    suites = AGENTDOJO_SUITES if include_suite else ("__overall__",)
    for suite in suites:
        for attack in _ATTACKS:
            for defense in _DEFENSES:
                values = grouped.get((suite, attack, defense), ())
                if not values:
                    continue
                targeted = _metric_summary(values, "targeted_attack_success", conservative_invalid=True)
                utility = _metric_summary(values, "utility", conservative_invalid=True)
                row: dict[str, Any] = {
                    "attack": attack,
                    "defense": defense,
                    "planned_n": len(values),
                    "valid_n": sum(item.valid for item in values),
                    "invalid_n": sum(not item.valid for item in values),
                    "targeted_asr": targeted,
                    "utility_under_attack": utility,
                }
                if include_suite:
                    row = {"suite": suite, **row}
                rows.append(row)
    return rows


def _clean_summary_rows(
    grouped: Mapping[tuple[str, str], Sequence[AgentDojoResultRecord]],
    *,
    include_suite: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    suites = AGENTDOJO_SUITES if include_suite else ("__overall__",)
    for suite in suites:
        for defense in _DEFENSES:
            values = grouped.get((suite, defense), ())
            if not values:
                continue
            utility = _metric_summary(values, "utility", conservative_invalid=True)
            row: dict[str, Any] = {
                "defense": defense,
                "planned_n": len(values),
                "valid_n": sum(item.valid for item in values),
                "invalid_n": sum(not item.valid for item in values),
                "utility_without_attack": utility,
            }
            if include_suite:
                row = {"suite": suite, **row}
            rows.append(row)
    return rows


def summarize_records(records: Iterable[AgentDojoResultRecord | Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize native formal records with both overall and suite strata.

    Single-suite callers retain the historical ``attack_summary`` and
    ``clean_utility`` shapes.  Multi-suite input additionally exposes
    ``overall_*`` (pooled denominators) and ``suite_*`` (independent suite
    denominators); no row is pooled across suites in the latter views.
    """

    parsed = [
        item if isinstance(item, AgentDojoResultRecord) else AgentDojoResultRecord.model_validate(item)
        for item in records
    ]
    if any(row.phase != "formal" for row in parsed):
        raise ValueError("summarize_records accepts formal records only")
    suites_present = tuple(sorted({row.suite for row in parsed}, key=lambda value: (AGENTDOJO_SUITES.index(value) if value in AGENTDOJO_SUITES else len(AGENTDOJO_SUITES), value)))
    multi_suite = len(suites_present) > 1

    grouped_attack_suite: dict[tuple[str, str, str], list[AgentDojoResultRecord]] = {}
    grouped_clean_suite: dict[tuple[str, str], list[AgentDojoResultRecord]] = {}
    for row in parsed:
        if row.attack == "none":
            grouped_clean_suite.setdefault((row.suite, row.defense), []).append(row)
        else:
            grouped_attack_suite.setdefault((row.suite, row.attack, row.defense), []).append(row)

    grouped_attack_overall: dict[tuple[str, str, str], list[AgentDojoResultRecord]] = {}
    grouped_clean_overall: dict[tuple[str, str], list[AgentDojoResultRecord]] = {}
    for (suite, attack, defense), values in grouped_attack_suite.items():
        grouped_attack_overall.setdefault(("__overall__", attack, defense), []).extend(values)
    for (suite, defense), values in grouped_clean_suite.items():
        grouped_clean_overall.setdefault(("__overall__", defense), []).extend(values)

    overall_attack_summary = _attack_summary_rows(grouped_attack_overall, include_suite=False)
    suite_attack_summary = _attack_summary_rows(grouped_attack_suite, include_suite=True)
    overall_clean_utility = _clean_summary_rows(grouped_clean_overall, include_suite=False)
    suite_clean_utility = _clean_summary_rows(grouped_clean_suite, include_suite=True)

    # Historical names are intentionally retained.  For the aggregate input,
    # they refer to pooled rows so existing consumers still receive a useful
    # table while new consumers can select the suite-stratified rows above.
    attack_summary = overall_attack_summary if multi_suite else [
        {key: value for key, value in row.items() if key != "suite"}
        for row in suite_attack_summary
    ]
    clean_utility = overall_clean_utility if multi_suite else [
        {key: value for key, value in row.items() if key != "suite"}
        for row in suite_clean_utility
    ]
    adapter_summary = []
    for defense in _DEFENSES:
        values = [row for row in parsed if row.defense == defense]
        if not values:
            continue
        adapter_records = sum(bool(row.adapter_mode) for row in values)
        decision_hashes = sum(bool(row.adapter_decision_sha256) for row in values)
        adapter_summary.append(
            {
                "defense": defense,
                "records": len(values),
                "adapter_records": adapter_records,
                "denied_calls": sum(row.adapter_denied_calls for row in values),
                "decision_hashes": decision_hashes,
                "missing_decision_hash": adapter_records - decision_hashes,
            }
        )
    return {
        "schema_version": "1",
        "record_count": len(parsed),
        "planned_n": len(parsed),
        "valid_n": sum(row.valid for row in parsed),
        "invalid_n": sum(not row.valid for row in parsed),
        "suite_count": len(suites_present),
        "suites": list(suites_present),
        "attack_summary": attack_summary,
        "clean_utility": clean_utility,
        "overall_attack_summary": overall_attack_summary,
        "suite_attack_summary": suite_attack_summary,
        "overall_clean_utility": overall_clean_utility,
        "suite_clean_utility": suite_clean_utility,
        "adapter_summary": adapter_summary,
    }

def _csv_value(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return value


def _write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields or ["row"], extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(value) for key, value in row.items()})


def _record_rows(records: Sequence[AgentDojoResultRecord]) -> list[dict[str, Any]]:
    return [record.model_dump(mode="json") for record in records]


def _flatten_metric_rows(rows: Sequence[Mapping[str, Any]], metric_key: str) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for row in rows:
        metric = dict(row[metric_key])
        flattened.append({key: value for key, value in row.items() if key != metric_key} | {
            f"{metric_key}_{key}": value for key, value in metric.items()
        })
    return flattened


def _tex_label(value: Any) -> str:
    return str(value).replace("_", "\\_")


def _publication_tex(report: Mapping[str, Any]) -> str:
    """Render a compact LaTeX table, adding a suite column for aggregates."""

    multi_suite = int(report.get("suite_count", 1)) > 1
    rows = report.get("suite_attack_summary", []) if multi_suite else report.get("attack_summary", [])
    clean_rows = report.get("suite_clean_utility", []) if multi_suite else report.get("clean_utility", [])
    first_col = "Suite & " if multi_suite else ""
    column_spec = "lllrrrrrr" if multi_suite else "llrrrrrr"
    lines = [
        "% Native AgentDojo external validation; attacks are intentionally separate.",
        f"\\begin{{tabular}}{{{column_spec}}}",
        first_col + "Attack / condition & Defense & Planned & Valid & Invalid & ASR/utility & ITT 95\\% CI & Valid-only " + "\\\\",
        "\\hline",
    ]
    for row in rows:
        asr = row["targeted_asr"]
        utility = row["utility_under_attack"]
        asr_ci = asr.get("wilson") or {}
        suite_prefix = f"{_tex_label(row['suite'])} & " if multi_suite else ""
        lines.append(
            f"{suite_prefix}{_tex_label(row['attack'])} ASR & {_tex_label(row['defense'])} & "
            f"{row['planned_n']} & {row['valid_n']} & {row['invalid_n']} & "
            f"{asr['itt_rate']:.3f} / {utility['itt_rate']:.3f} & "
            f"[{asr_ci.get('lower', 0):.3f},{asr_ci.get('upper', 0):.3f}] & "
            + (f"{asr.get('valid_only_rate') if asr.get('valid_only_rate') is not None else 'NA'} " + "\\\\"),
        )
    for row in clean_rows:
        metric = row["utility_without_attack"]
        ci = metric.get("wilson") or {}
        suite_prefix = f"{_tex_label(row['suite'])} & " if multi_suite else ""
        lines.append(
            f"{suite_prefix}Clean utility & {_tex_label(row['defense'])} & {row['planned_n']} & "
            f"{row['valid_n']} & {row['invalid_n']} & {metric['itt_rate']:.3f} & "
            f"[{ci.get('lower', 0):.3f},{ci.get('upper', 0):.3f}] & "
            + (f"{metric.get('valid_only_rate') if metric.get('valid_only_rate') is not None else 'NA'} " + "\\\\"),
        )
    lines.extend(["\\end{tabular}", ""])
    return "\n".join(lines)

def _fallback_png(path: Path, *, panels: int = 2) -> None:
    """Write a small real PNG when matplotlib is unavailable."""
    panels = max(1, int(panels))
    panel_width = 72
    width, height = panel_width * panels + 16, 80
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            panel = min(panels - 1, max(0, (x - 8) // panel_width))
            within = (x - 8) % panel_width
            if 8 < x < width - 8 and 12 < y < 68 and within > 4:
                color = (76, 120, 168) if y > 40 else (245, 133, 24)
            else:
                color = (255, 255, 255)
            row.extend(color)
        rows.append(bytes(row))
    raw = b"".join(rows)
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    payload = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    with path.open("xb") as handle:
        handle.write(payload)

def _plot(path: Path, report: Mapping[str, Any]) -> None:
    """Plot attack ASR by suite (four panels for the full benchmark)."""
    multi_suite = int(report.get("suite_count", 1)) > 1
    suites = list(report.get("suites", [])) if multi_suite else []
    if not suites:
        suites = ["__overall__"]
    rows = report.get("suite_attack_summary", []) if multi_suite else report.get("attack_summary", [])
    ncols = 2
    nrows = (len(suites) + ncols - 1) // ncols
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        _fallback_png(path, panels=len(suites))
        return
    fig, axes = plt.subplots(nrows, ncols, figsize=(8.0, 3.4 * nrows), squeeze=False, sharey=True)
    flat_axes = list(axes.flat)
    for index, suite in enumerate(suites):
        ax = flat_axes[index]
        subset = [row for row in rows if (row.get("suite", "__overall__") == suite)]
        values_by_attack: dict[str, list[float]] = {}
        for attack in _ATTACKS:
            values_by_attack[attack] = []
            attack_rows = [row for row in subset if row["attack"] == attack]
            for defense in _DEFENSES:
                found = next((row for row in attack_rows if row["defense"] == defense), None)
                values_by_attack[attack].append((found or {}).get("targeted_asr", {}).get("itt_rate", 0.0))
        # Keep one bar per defense, grouped by attack.  Scale the bar width so
        # seven transfer arms remain readable without overlapping neighboring
        # attack groups; the two-arm baseline retains the wider historical bars.
        x = list(range(len(_ATTACKS)))
        width = min(0.35, 0.8 / len(_DEFENSES))
        for offset, defense in enumerate(_DEFENSES):
            vals = [values_by_attack[attack][offset] for attack in _ATTACKS]
            centre = (len(_DEFENSES) - 1) / 2
            ax.bar([item + (offset - centre) * width for item in x], vals, width=width, label=defense.replace("_", " "))
        ax.set_xticks(x, [attack.replace("_", " ").title() for attack in _ATTACKS])
        ax.set_title("Overall" if suite == "__overall__" else suite.title())
        ax.set_ylabel("Targeted ASR (ITT)")
        ax.set_ylim(0.0, 1.0)
        ax.tick_params(axis="x", rotation=18)
        ax.legend(fontsize=7)
    for ax in flat_axes[len(suites):]:
        ax.axis("off")
    fig.tight_layout()
    with path.open("xb") as handle:
        fig.savefig(handle, format="png", dpi=160)
    plt.close(fig)

def write_analysis_bundle(
    records: Sequence[AgentDojoResultRecord],
    output_dir: str | Path,
    *,
    plan_hash: str,
    attempt_selection_hash: str = "",
    input_record_hashes: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Exclusively create all publication files and return the manifest."""

    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=False)
    report = summarize_records(records)
    record_rows = _record_rows(records)
    multi_suite = int(report.get("suite_count", 1)) > 1
    attack_rows = report["suite_attack_summary"] if multi_suite else report["attack_summary"]
    clean_rows = report["suite_clean_utility"] if multi_suite else report["clean_utility"]
    outputs: dict[str, Any] = {
        "records.json": record_rows,
        "records.csv": record_rows,
        "attack_summary.json": attack_rows,
        "attack_summary.csv": [
            {**base, **{f"utility_under_attack_{key}": value for key, value in row["utility_under_attack"].items()}}
            for row, base in ((row, {**flat, "attack": row["attack"], "defense": row["defense"]}) for row, flat in zip(attack_rows, _flatten_metric_rows(attack_rows, "targeted_asr"), strict=True))
        ],
        "clean_utility.json": clean_rows,
        "clean_utility.csv": _flatten_metric_rows(clean_rows, "utility_without_attack"),
        "publication_table.tex": _publication_tex(report),
        "results_summary.json": report | {"metadata": dict(metadata or {})},
    }
    for name, value in outputs.items():
        if name.endswith(".json"):
            _write_json(root / name, value)
        elif name.endswith(".csv"):
            _write_csv(root / name, value)
        else:
            with (root / name).open("x", encoding="utf-8") as handle:
                handle.write(value)
    _plot(root / "agentdojo_outcomes.png", report)

    hashes: dict[str, str] = {name: _sha256_file(root / name) for name in (
        "records.json", "records.csv", "attack_summary.json", "attack_summary.csv",
        "clean_utility.json", "clean_utility.csv", "publication_table.tex",
        "agentdojo_outcomes.png", "results_summary.json",
    )}
    manifest = {
        "schema_version": "1",
        "analysis": "agentdojo_external_formal",
        "plan_sha256": plan_hash,
        "attempt_selection_sha256": attempt_selection_hash,
        "record_count": len(records),
        "suite_count": report.get("suite_count", 1),
        "suites": report.get("suites", []),
        "input_record_sha256": dict(sorted((input_record_hashes or {}).items())),
        "outputs": hashes,
        "output_sha256": hashes,
    }
    _write_json(root / "analysis_manifest.json", manifest)
    return manifest


def analyze_records(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Backward-compatible alias for :func:`write_analysis_bundle`."""
    return write_analysis_bundle(*args, **kwargs)


__all__ = [
    "analyze_records",
    "summarize_records",
    "validate_formal_records",
    "write_analysis_bundle",
]
