# Artifact aggregation and pilot gates

Analysis consumes only complete, flat `record.json` files written last by the
orchestrator. It recursively discovers records, validates every RunSpec and
RunResult field, recomputes each `run_id`, and rejects any repeated run ID. Thus
an artifact root containing both `attempt-0001` and a retry for the same run is
intentionally ambiguous; prepare an ITT root with exactly the pre-declared
attempt for each run instead of selecting a retry from its outcome.

For formal results, require an exact match to the verified frozen plan:

```bash
conda run -n test python scripts/analyze_results.py \
  --artifact-root artifacts/formal-v1 \
  --plan-dir configs/frozen/formal_plan_v1 \
  --output-dir artifacts/formal-analysis-v1
```

The new output directory contains validated record JSON/CSV, cell and arm
summaries with valid-only and ITT Wilson intervals, fixed-seed paired-bootstrap
contrasts, publication CSV/LaTeX tables, three PNG figures, and a manifest of
input/output SHA-256 hashes. `--no-plots` is available on a controller without
the optional Matplotlib dependency.

Pilot gates must be run on development-payload artifacts only:

```bash
conda run -n test python scripts/evaluate_pilot.py \
  --artifact-root artifacts/pilot-development-itt \
  --output artifacts/pilot-gates.json
```

Exit status is zero only when all five pre-declared gates pass. Infrastructure
failures remain in every gate denominator. The exposure gate applies to all
selected pilot records by default; the Python API permits narrowing it only to
a pre-declared list of intended-exposure run IDs. The report is written with
exclusive creation so an earlier gate decision is never overwritten.
