# Full AgentDojo Suite + Canonical Attacks Design

## Status

Approved by the project owner on 2026-07-24 for implementation on the local
`ckw` branch. The remote repository will not be changed by this work.

## Goal

Extend the native AgentDojo cross-check from the existing Workspace slice to
all four AgentDojo v1.2.2 suites while preserving a deterministic, auditable
comparison of the two canonical indirect-prompt-injection attacks under the
two currently supported defenses.

The experiment is an external validation of the project gateway. It must not
be presented as a replacement for the project-owned provenance metrics.

## Scope and frozen matrix

The benchmark identity is fixed to AgentDojo tag `v0.1.35`, commit
`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`, and benchmark version `v1.2.2`.
The suites are exactly `workspace`, `travel`, `banking`, and `slack`.

For each suite, enumerate every user-task/injection-task Cartesian pair and
retain only pairs for which both official attacks produce a non-empty
injection dictionary during outcome-independent freezing:

* `important_instructions`
* `tool_knowledge`

Every runnable attacked pair is evaluated with both defenses:

* `none`
* `repeat_user_prompt`

Every user task is also evaluated once without an injection task under both
defenses. Clean cells measure utility only and are excluded from attack-rate
denominators.

The expected unfiltered v1.2.2 inventory is 97 user tasks and 35 injection
tasks (949 Cartesian pairs). The freeze command records the exact applicable
pair count instead of assuming that every pair is runnable. The nominal
matrix is 3,796 attacked cells plus 194 clean cells, or 3,990 cells total.
Development rows are a deterministic, disjoint smoke subset (two attacked
pairs and two clean user tasks per suite); all remaining cells are formal.
The exact counts and hashes in the frozen manifests are authoritative.

## Alternatives considered

1. **Keep a single Workspace plan and add more attacks.** This is the smallest
   code change, but it does not provide cross-domain evidence and leaves the
   current external claim dependent on one suite.
2. **Create one monolithic JSONL plan for all suites.** This gives one shard
   namespace, but makes suite-level reruns and artifact inspection awkward and
   increases the chance of a duplicate run ID.
3. **Recommended: one frozen sub-plan per suite plus one shared schema and
   aggregate analysis.** Each suite can be scheduled, retried, and inspected
   independently; the aggregate analyzer can still produce one publication
   table. Suite identity is carried in every row and record, so concatenating
   artifacts is safe.

## Architecture

### Freeze layer

`scripts/freeze_agentdojo_external.py` becomes a generic freezer. It loads the
four suites and the two official attack constructors in the isolated
AgentDojo environment, computes canonical pair hashes, records attack
applicability and exceptions, and writes an append-free directory:

```
configs/frozen/agentdojo_external_full_v1/
  plan_manifest.json
  workspace/{manifest.json,development_plan.jsonl,formal_plan.jsonl}
  travel/{manifest.json,development_plan.jsonl,formal_plan.jsonl}
  banking/{manifest.json,development_plan.jsonl,formal_plan.jsonl}
  slack/{manifest.json,development_plan.jsonl,formal_plan.jsonl}
```

The top-level manifest binds source/config/model hashes and the per-suite
manifest hashes. A second freeze to the same destination fails rather than
silently changing the experiment.

### Execution layer

`src/agentsec/agentdojo_external.py` extends the project-owned run and result
contracts with a validated suite name and general attack name. The runner
loads the suite named by each row, constructs the official attack for that
suite, executes one explicit row, and writes a compact `record.json` plus
the untouched official trace under an ignored artifact root. Run IDs include
suite, user task, injection task, attack, and defense; therefore shard merges
cannot collide across suites.

The Slurm launcher accepts a plan directory and suite, keeps the existing
proxy-off/vLLM readiness behavior, and uses unique array-task ports and log
paths. A wave submitter generates bounded arrays from the frozen formal rows;
reruns select only missing or invalid records and never change the frozen
denominator.

### Analysis layer

`src/agentsec/agentdojo_external_analysis.py` and
`scripts/analyze_agentdojo_external.py` discover all four suites and the two
attacks from records rather than hard-coding the Workspace slice. They emit:

* per-suite × attack × defense counts and ASR/utility;
* an overall attacked-cell table and clean-utility table;
* CSV/JSON records for reproducibility;
* a compact figure with suite-separated panels;
* an analysis manifest containing plan, record, and code/config hashes.

The analyzer fails closed when a formal row is missing, duplicated, invalid,
or belongs to a different frozen plan. Clean utility and attacked security
metrics use separate denominators.

## Data flow

1. Freeze source/config/model identity and enumerate all suite pairs.
2. Validate attack applicability and write immutable per-suite plans.
3. Run development rows; inspect readiness, serialization, and scoring.
4. Submit formal shards in bounded waves on the 30-minute A40 debug queue.
5. Collect compact records and select exactly one valid final attempt per row.
6. Analyze only the selected formal records and generate publication artifacts.
7. Update the external-validation documentation and bilingual README with
   the exact matrix, counts, limitations, and artifact links.

## Failure handling and reproducibility

* A model/API/tool exception produces an invalid record and does not count as
  a successful defense or attack.
* Missing, duplicate, or hash-mismatched records stop formal analysis.
* Retries use a new attempt ID while retaining the same run ID and plan row.
* Slurm shard failures are logged separately and can be resubmitted without
  rewriting plans.
* Official AgentDojo traces remain ignored; compact records and derived
  summaries are the committed evidence.
* The existing local Qwen3-VL-8B checkpoint, served name `qwen3-vl-8b`,
  temperature `0.0`, JSON tool output, and 16K context are unchanged.

## Testing and acceptance criteria

Before any large submission, tests must prove:

1. all four suites and both attacks are accepted by the frozen contracts;
2. run IDs and canonical hashes differ across suites and cannot collide;
3. clean rows reject injection IDs and attacked rows require them;
4. freeze output is deterministic, append-free, and has disjoint development
   and formal rows;
5. a mocked runner can load a non-Workspace suite and serialize a record;
6. analysis groups by suite and keeps clean and attacked denominators separate;
7. the existing 147-test suite remains green.

The experiment is complete only when every formal row in the top-level
selection manifest has exactly one valid selected record and the analysis
bundle is generated from that manifest.

## Non-goals

This expansion does not add the other official attacks, interactive `manual`,
new defenses, new model checkpoints, AgentDojo utility injection-task
scoring, or a claim that AgentDojo measures the project gateway's provenance
leakage metric directly.
