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

from .agentdojo_external import AgentDojoResultRecord, AgentDojoRunSpec
from .aggregate import wilson_interval
from .attempts import AttemptSelectionManifest, INFRASTRUCTURE_REASONS

_ATTACKS = ("important_instructions", "tool_knowledge")
_DEFENSES = ("none", "repeat_user_prompt")
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


def summarize_records(records: Iterable[AgentDojoResultRecord | Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize attacks separately and clean utility by defense.

    The returned dictionary is intentionally JSON-native.  ``attack_summary``
    has one row for each attack/defense pair and includes targeted ASR and
    utility-under-attack metrics.  ``clean_utility`` has one row per defense.
    """

    parsed = [item if isinstance(item, AgentDojoResultRecord) else AgentDojoResultRecord.model_validate(item) for item in records]
    if any(row.phase != "formal" for row in parsed):
        raise ValueError("summarize_records accepts formal records only")
    grouped_attack: dict[tuple[str, str], list[AgentDojoResultRecord]] = {}
    grouped_clean: dict[str, list[AgentDojoResultRecord]] = {}
    for row in parsed:
        if row.attack == "none":
            grouped_clean.setdefault(row.defense, []).append(row)
        else:
            grouped_attack.setdefault((row.attack, row.defense), []).append(row)

    attack_summary: list[dict[str, Any]] = []
    for attack in _ATTACKS:
        for defense in _DEFENSES:
            rows = grouped_attack.get((attack, defense), [])
            if not rows:
                continue
            targeted = _metric_summary(rows, "targeted_attack_success", conservative_invalid=True)
            utility = _metric_summary(rows, "utility", conservative_invalid=True)
            attack_summary.append(
                {
                    "attack": attack,
                    "defense": defense,
                    "planned_n": len(rows),
                    "valid_n": sum(row.valid for row in rows),
                    "invalid_n": sum(not row.valid for row in rows),
                    "targeted_asr": targeted,
                    "utility_under_attack": utility,
                }
            )

    clean_utility: list[dict[str, Any]] = []
    for defense in _DEFENSES:
        rows = grouped_clean.get(defense, [])
        if not rows:
            continue
        utility = _metric_summary(rows, "utility", conservative_invalid=True)
        clean_utility.append(
            {
                "defense": defense,
                "planned_n": len(rows),
                "valid_n": sum(row.valid for row in rows),
                "invalid_n": sum(not row.valid for row in rows),
                "utility_without_attack": utility,
            }
        )
    return {
        "schema_version": "1",
        "record_count": len(parsed),
        "planned_n": len(parsed),
        "valid_n": sum(row.valid for row in parsed),
        "invalid_n": sum(not row.valid for row in parsed),
        "attack_summary": attack_summary,
        "clean_utility": clean_utility,
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
    lines = [
        "% Native AgentDojo external validation; attacks are intentionally separate.",
        "\\begin{tabular}{llrrrrrr}",
        "Attack / condition & Defense & Planned & Valid & Invalid & ASR/utility & ITT 95\\% CI & Valid-only " + r"\\",
        "\\hline",
    ]
    for row in report["attack_summary"]:
        asr = row["targeted_asr"]
        utility = row["utility_under_attack"]
        asr_ci = asr.get("wilson") or {}
        util_ci = utility.get("wilson") or {}
        lines.append(
            f"{_tex_label(row['attack'])} ASR & {_tex_label(row['defense'])} & "
            f"{row['planned_n']} & {row['valid_n']} & {row['invalid_n']} & "
            f"{asr['itt_rate']:.3f} / {utility['itt_rate']:.3f} & "
            f"[{asr_ci.get('lower', 0):.3f},{asr_ci.get('upper', 0):.3f}] & " +
            (f"{asr.get('valid_only_rate') if asr.get('valid_only_rate') is not None else 'NA'} " + r"\\"),
        )
    for row in report["clean_utility"]:
        metric = row["utility_without_attack"]
        ci = metric.get("wilson") or {}
        lines.append(
            f"Clean utility & {_tex_label(row['defense'])} & {row['planned_n']} & "
            f"{row['valid_n']} & {row['invalid_n']} & {metric['itt_rate']:.3f} & "
            f"[{ci.get('lower', 0):.3f},{ci.get('upper', 0):.3f}] & " +
            (f"{metric.get('valid_only_rate') if metric.get('valid_only_rate') is not None else 'NA'} " + r"\\"),
        )
    lines.extend(["\\end{tabular}", ""])
    return "\n".join(lines)


def _fallback_png(path: Path) -> None:
    """Write a small real two-panel PNG when matplotlib is unavailable."""
    width, height = 160, 80
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            if 8 < x < 76 and 12 < y < 68:
                color = (76, 120, 168) if y > 40 else (245, 133, 24)
            elif 84 < x < 152 and 12 < y < 68:
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
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        _fallback_png(path)
        return
    fig, axes = plt.subplots(1, 2, figsize=(8.0, 3.4), sharey=True)
    attack_rows = report.get("attack_summary", [])
    for ax, attack in zip(axes, _ATTACKS):
        subset = [row for row in attack_rows if row["attack"] == attack]
        labels = ["None", "Repeat user prompt"]
        values = []
        for defense in _DEFENSES:
            found = next((row for row in subset if row["defense"] == defense), None)
            values.append((found or {}).get("targeted_asr", {}).get("itt_rate", 0.0))
        ax.bar(labels, values, color=("#4c78a8", "#f58518"))
        ax.set_title(attack.replace("_", " ").title())
        ax.set_ylabel("Targeted ASR (ITT)" if ax is axes[0] else "")
        ax.set_ylim(0.0, 1.0)
        ax.tick_params(axis="x", rotation=18)
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
    attack_rows = report["attack_summary"]
    clean_rows = report["clean_utility"]
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
