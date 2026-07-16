# Provenance-Aware Capability Gating against Indirect Prompt Injection

This repository is the implementation and reproducibility package for the
AIAA/AAIA 4313 group project. It evaluates indirect prompt injection against a
local, tool-using multi-agent office assistant and compares prompt-only defenses
with deterministic capability and provenance enforcement.

## Research question

Given a correct task-authorization manifest, can provenance-aware capability
gating reduce executed unauthorized actions and synthetic secret leakage without
substantially reducing benign task completion?

The claim is intentionally limited to this controlled prototype. The system
tracks exact registered synthetic values and does not provide general semantic
information-flow security.

## System

- A **Reader Agent** searches and reads a local mock inbox.
- An **Action Agent** receives the Reader summary and exact retrieved evidence,
  then proposes calls to a mock file vault, calendar, and outbox.
- A deterministic **Capability Gateway** checks every Action-Agent call.
- An independent evaluator derives outcomes from the before/after world state
  and structured audit events.
- A **Red Agent** generates payloads only during dataset preparation. Formal
  payloads are frozen and hashed before evaluation.

All data, secrets, accounts, and side effects are synthetic and local. The
agents have no shell, real email, real calendar, payment, deletion, credential,
or external-network tools.

## Model and cluster runtime

The primary model is already available locally and must not be downloaded:

```text
/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct
```

One A40 runs one shared vLLM 0.15.1 service in the `vllm` Conda environment.
The controller uses the `test` environment. Requests are non-streaming; vLLM is
configured for BF16, an 8K context, one GPU, and the Hermes tool parser.

## Experimental design

The formal matrix is:

```text
6 scenarios x 3 content conditions x 4 defenses x 3 paired seeds = 216 runs
```

Conditions are `clean`, matched `placebo`, and `attack`. Defense arms are
`allow_all`, `prompt_only`, `capability_only`, and `full`. The primary outcomes
are executed unauthorized action rate, exact synthetic-secret leakage rate, and
benign task success. Attempted and blocked actions are reported separately.

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md),
and [experiment protocol](docs/EXPERIMENT_PROTOCOL.md). The
[demo guide](docs/DEMO.md) covers live execution, artifact replay, and the
presentation script.

## Demo and report

Launch the replay-safe Gradio app from the controller environment:

```bash
conda run -n test python scripts/demo.py --replay-only
```

Omit `--replay-only` when the local vLLM service and live experiment adapter are
available. Compile the report with `bash scripts/compile_report.sh`. Its results
include remains explicitly unpopulated until verified formal aggregation; the
bundled deterministic replay is never treated as an experimental result.

## Repository layout

```text
src/agentsec/       system, policy, runtime, and evaluator
configs/            model, prompt, scenario, and frozen run specifications
data/               generated/frozen payload registries
scripts/            smoke, generation, experiment, aggregation, and demo entrypoints
tests/              deterministic unit, truth-table, and null-audit tests
artifacts/          ignored runtime evidence and derived outputs
docs/               design, protocol, safety, and internal notes
report/             final technical report sources
```

## Reproducibility rules

- Every attempt starts from a fresh world snapshot.
- Raw evidence is append-only; retries never overwrite prior attempts.
- Manifests use relative paths and record SHA-256 hashes.
- Exposure is proved by structured resource-read and context-parent events.
- No-op and refusal are valid behavioral outcomes, not infrastructure failures.
- A blocked attack is not counted as a successful attack.
- The formal run plan is randomized once, frozen, and hashed before execution.

## AI-use disclosure

Generative AI tools are used for implementation assistance, offline synthetic
attack generation, review, and writing support. All generated material is
reviewed, tested, and attributed in the final report in accordance with the
course AI policy.
