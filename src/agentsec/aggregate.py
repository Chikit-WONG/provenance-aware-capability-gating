"""Deterministic aggregation for the pre-registered experiment contrasts.

The helpers in this module deliberately accept either Pydantic records or plain
dictionaries.  This keeps analysis independent from the persistence layer and
makes it possible to audit exported JSONL without importing the runtime.
"""

from __future__ import annotations

from collections import defaultdict
from math import sqrt
from random import Random
from statistics import NormalDist
from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field


DEFAULT_PAIR_FIELDS = ("scenario_id", "seed", "repetition", "model_config_hash")


class WilsonInterval(BaseModel):
    """A two-sided Wilson score interval for a Bernoulli proportion."""

    model_config = ConfigDict(frozen=True)

    lower: float
    upper: float
    confidence: float


class BinaryMetricSummary(BaseModel):
    """One grouped binary outcome, retaining infrastructure failures in ITT."""

    model_config = ConfigDict(frozen=True)

    group: dict[str, str | int | bool | None]
    metric: str
    planned_n: int = Field(ge=0)
    valid_n: int = Field(ge=0)
    invalid_n: int = Field(ge=0)
    successes: int = Field(ge=0)
    valid_successes: int = Field(ge=0)
    invalid_successes: int = Field(ge=0)
    itt_rate: float | None
    itt_lower_bound_rate: float | None
    itt_upper_bound_rate: float | None
    valid_only_rate: float | None
    itt_wilson: WilsonInterval | None
    valid_only_wilson: WilsonInterval | None


class PairedComparison(BaseModel):
    """A paired risk difference plus audit information about missing pairs."""

    model_config = ConfigDict(frozen=True)

    name: str
    metric: str
    left_selector: dict[str, str | int | bool | None]
    right_selector: dict[str, str | int | bool | None]
    matched_n: int = Field(ge=0)
    valid_pair_n: int = Field(ge=0)
    invalid_pair_n: int = Field(ge=0)
    unmatched_left_n: int = Field(ge=0)
    unmatched_right_n: int = Field(ge=0)
    left_successes: int = Field(ge=0)
    right_successes: int = Field(ge=0)
    left_rate: float | None
    right_rate: float | None
    left_wilson: WilsonInterval | None
    right_wilson: WilsonInterval | None
    risk_difference: float | None
    risk_difference_ci: tuple[float, float] | None
    valid_left_successes: int = Field(ge=0)
    valid_right_successes: int = Field(ge=0)
    valid_left_rate: float | None
    valid_right_rate: float | None
    valid_left_wilson: WilsonInterval | None
    valid_right_wilson: WilsonInterval | None
    valid_risk_difference: float | None
    valid_risk_difference_ci: tuple[float, float] | None
    ci_method: str = "paired_percentile_bootstrap"
    bootstrap_seed: int = 4313
    bootstrap_resamples: int = Field(default=10_000, ge=1)


def wilson_interval(
    successes: int,
    total: int,
    *,
    confidence: float = 0.95,
) -> WilsonInterval | None:
    """Return a Wilson score interval, or ``None`` for an empty sample."""

    if total < 0:
        raise ValueError("total must be non-negative")
    if successes < 0 or successes > total:
        raise ValueError("successes must be between zero and total")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be strictly between zero and one")
    if total == 0:
        return None

    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    p_hat = successes / total
    z2_over_n = z * z / total
    centre = (p_hat + z2_over_n / 2.0) / (1.0 + z2_over_n)
    half_width = (
        z
        * sqrt((p_hat * (1.0 - p_hat) + z * z / (4.0 * total)) / total)
        / (1.0 + z2_over_n)
    )
    return WilsonInterval(
        lower=max(0.0, centre - half_width),
        upper=min(1.0, centre + half_width),
        confidence=confidence,
    )


def summarize_binary_metric(
    records: Iterable[Any],
    metric: str,
    *,
    group_by: Sequence[str] = ("scenario_id", "content_condition", "defense_arm"),
    confidence: float = 0.95,
) -> list[BinaryMetricSummary]:
    """Summarize a binary field without dropping invalid planned runs.

    The pre-registered intention-to-test (ITT) denominator includes invalid
    infrastructure outcomes. Bounds additionally treat unresolved invalid
    outcomes as all failures or all successes, so sensitivity is explicit.
    """

    grouped: dict[tuple[Any, ...], list[Any]] = defaultdict(list)
    for record in records:
        grouped[tuple(_normalise(_field(record, name)) for name in group_by)].append(record)

    summaries: list[BinaryMetricSummary] = []
    for key in sorted(grouped, key=lambda value: tuple(str(item) for item in value)):
        rows = grouped[key]
        planned_n = len(rows)
        valid_rows = [row for row in rows if bool(_field(row, "valid", default=True))]
        successes = sum(bool(_field(row, metric)) for row in rows)
        valid_successes = sum(bool(_field(row, metric)) for row in valid_rows)
        valid_n = len(valid_rows)
        invalid_successes = successes - valid_successes
        unresolved_invalid = planned_n - valid_n - invalid_successes
        summaries.append(
            BinaryMetricSummary(
                group=dict(zip(group_by, key)),
                metric=metric,
                planned_n=planned_n,
                valid_n=valid_n,
                invalid_n=planned_n - valid_n,
                successes=successes,
                valid_successes=valid_successes,
                invalid_successes=invalid_successes,
                itt_rate=successes / planned_n if planned_n else None,
                itt_lower_bound_rate=successes / planned_n if planned_n else None,
                itt_upper_bound_rate=(
                    (successes + unresolved_invalid) / planned_n if planned_n else None
                ),
                valid_only_rate=valid_successes / valid_n if valid_n else None,
                itt_wilson=wilson_interval(successes, planned_n, confidence=confidence),
                valid_only_wilson=wilson_interval(
                    valid_successes, valid_n, confidence=confidence
                ),
            )
        )
    return summaries


def paired_comparison(
    records: Iterable[Any],
    *,
    name: str,
    metric: str,
    left_selector: Mapping[str, Any],
    right_selector: Mapping[str, Any],
    pair_by: Sequence[str] = DEFAULT_PAIR_FIELDS,
    confidence: float = 0.95,
    bootstrap_seed: int = 4313,
    bootstrap_resamples: int = 10_000,
) -> PairedComparison:
    """Compare two treatments using only exact, pre-registered matched pairs.

    Duplicate records for the same treatment and pair key are rejected because
    selecting one would make the analysis order-dependent. Matched invalid runs
    remain in ITT with their observed state-derived outcome and are reported.
    """

    if bootstrap_resamples < 1:
        raise ValueError("bootstrap_resamples must be positive")
    rows = list(records)
    left = _index_selected(rows, left_selector, pair_by)
    right = _index_selected(rows, right_selector, pair_by)
    left_keys = set(left)
    right_keys = set(right)
    matched_keys = sorted(
        left_keys & right_keys, key=lambda value: tuple(str(item) for item in value)
    )

    left_values: list[int] = []
    right_values: list[int] = []
    pair_differences: list[int] = []
    valid_left_values: list[int] = []
    valid_right_values: list[int] = []
    valid_pair_differences: list[int] = []
    invalid_pair_n = 0
    for key in matched_keys:
        left_row = left[key]
        right_row = right[key]
        left_value = int(bool(_field(left_row, metric)))
        right_value = int(bool(_field(right_row, metric)))
        left_values.append(left_value)
        right_values.append(right_value)
        pair_differences.append(left_value - right_value)
        if not (
            bool(_field(left_row, "valid", default=True))
            and bool(_field(right_row, "valid", default=True))
        ):
            invalid_pair_n += 1
        else:
            valid_left_values.append(left_value)
            valid_right_values.append(right_value)
            valid_pair_differences.append(left_value - right_value)

    matched_n = len(matched_keys)
    left_successes = sum(left_values)
    right_successes = sum(right_values)
    valid_left_successes = sum(valid_left_values)
    valid_right_successes = sum(valid_right_values)
    valid_pair_n = len(valid_pair_differences)
    return PairedComparison(
        name=name,
        metric=metric,
        left_selector={key: _normalise(value) for key, value in left_selector.items()},
        right_selector={key: _normalise(value) for key, value in right_selector.items()},
        matched_n=matched_n,
        valid_pair_n=valid_pair_n,
        invalid_pair_n=invalid_pair_n,
        unmatched_left_n=len(left_keys - right_keys),
        unmatched_right_n=len(right_keys - left_keys),
        left_successes=left_successes,
        right_successes=right_successes,
        left_rate=left_successes / matched_n if matched_n else None,
        right_rate=right_successes / matched_n if matched_n else None,
        left_wilson=wilson_interval(left_successes, matched_n, confidence=confidence),
        right_wilson=wilson_interval(right_successes, matched_n, confidence=confidence),
        risk_difference=(sum(pair_differences) / matched_n if matched_n else None),
        risk_difference_ci=_paired_bootstrap_interval(
            pair_differences,
            confidence=confidence,
            seed=bootstrap_seed,
            resamples=bootstrap_resamples,
        ),
        valid_left_successes=valid_left_successes,
        valid_right_successes=valid_right_successes,
        valid_left_rate=(valid_left_successes / valid_pair_n if valid_pair_n else None),
        valid_right_rate=(valid_right_successes / valid_pair_n if valid_pair_n else None),
        valid_left_wilson=wilson_interval(
            valid_left_successes, valid_pair_n, confidence=confidence
        ),
        valid_right_wilson=wilson_interval(
            valid_right_successes, valid_pair_n, confidence=confidence
        ),
        valid_risk_difference=(
            sum(valid_pair_differences) / valid_pair_n if valid_pair_n else None
        ),
        valid_risk_difference_ci=_paired_bootstrap_interval(
            valid_pair_differences,
            confidence=confidence,
            seed=bootstrap_seed,
            resamples=bootstrap_resamples,
        ),
        bootstrap_seed=bootstrap_seed,
        bootstrap_resamples=bootstrap_resamples,
    )


def planned_comparisons(
    records: Iterable[Any],
    *,
    metric: str = "executed_unauthorized_effect",
    confidence: float = 0.95,
) -> list[PairedComparison]:
    """Produce the three contrasts fixed in ``docs/ARCHITECTURE.md``."""

    rows = list(records)
    comparisons = [
        paired_comparison(
            rows,
            name="attack_minus_placebo_under_allow_all",
            metric=metric,
            left_selector={
                "content_condition": "attack",
                "defense_arm": "allow_all",
            },
            right_selector={
                "content_condition": "placebo",
                "defense_arm": "allow_all",
            },
            confidence=confidence,
        ),
        paired_comparison(
            rows,
            name="full_minus_allow_all_under_attack",
            metric=metric,
            left_selector={"content_condition": "attack", "defense_arm": "full"},
            right_selector={
                "content_condition": "attack",
                "defense_arm": "allow_all",
            },
            confidence=confidence,
        ),
    ]

    provenance_rows = [
        row for row in rows if _normalise(_field(row, "scenario_id")) in {"T5", "T6"}
    ]
    comparisons.append(
        paired_comparison(
            provenance_rows,
            name="full_minus_capability_only_on_t5_t6_attack",
            metric=metric,
            left_selector={"content_condition": "attack", "defense_arm": "full"},
            right_selector={
                "content_condition": "attack",
                "defense_arm": "capability_only",
            },
            confidence=confidence,
        )
    )
    return comparisons


def _index_selected(
    rows: Sequence[Any], selector: Mapping[str, Any], pair_by: Sequence[str]
) -> dict[tuple[Any, ...], Any]:
    index: dict[tuple[Any, ...], Any] = {}
    for row in rows:
        if not all(
            _normalise(_field(row, field)) == _normalise(expected)
            for field, expected in selector.items()
        ):
            continue
        key = tuple(_normalise(_field(row, field)) for field in pair_by)
        if key in index:
            raise ValueError(f"duplicate treatment record for pair key {key!r}")
        index[key] = row
    return index


def _paired_bootstrap_interval(
    differences: Sequence[int], *, confidence: float, seed: int, resamples: int
) -> tuple[float, float] | None:
    if not differences:
        return None
    if len(differences) == 1:
        mean = float(differences[0])
        return (mean, mean)
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be strictly between zero and one")
    if resamples < 1:
        raise ValueError("resamples must be positive")
    generator = Random(seed)
    size = len(differences)
    estimates = sorted(
        sum(differences[generator.randrange(size)] for _ in range(size)) / size
        for _ in range(resamples)
    )
    alpha = (1.0 - confidence) / 2.0
    return (_percentile(estimates, alpha), _percentile(estimates, 1.0 - alpha))


def _percentile(sorted_values: Sequence[float], quantile: float) -> float:
    if not sorted_values:
        raise ValueError("cannot take a percentile of an empty sequence")
    position = quantile * (len(sorted_values) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


_MISSING = object()


def _field(record: Any, name: str, default: Any = _MISSING) -> Any:
    if isinstance(record, Mapping):
        if name in record:
            return record[name]
        nested_records = (record.get("run_spec"), record.get("result"))
    elif hasattr(record, name):
        return getattr(record, name)
    else:
        nested_records = (
            getattr(record, "run_spec", None),
            getattr(record, "result", None),
        )
    for nested in nested_records:
        if nested is None or nested is record:
            continue
        try:
            return _field(nested, name)
        except KeyError:
            pass
    if default is not _MISSING:
        return default
    raise KeyError(f"record has no field {name!r}")


def _normalise(value: Any) -> Any:
    return getattr(value, "value", value)
