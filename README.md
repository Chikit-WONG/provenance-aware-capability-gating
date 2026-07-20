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

A separately frozen follow-up adds the fifth arm `prompt_capability_only`
(safe prompt and capability checks, without provenance sink checks):

```text
6 scenarios x 3 content conditions x 1 additional defense x 3 paired seeds
= 54 add-on runs
```

This add-on isolates Full minus Prompt+Capability while leaving the original
216-run formal study and its reported results unchanged.

The completed two-by-two follow-up also adds 54 `capability_provenance_only`
runs (capability plus provenance, without the safe prompt), for 324 planned
victim runs in the combined analysis. A deterministic 16-case sink-pressure
test separately exercises malicious values at email subject/body and calendar
title/location sinks.

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md),
and [experiment protocol](docs/EXPERIMENT_PROTOCOL.md). The
[demo guide](docs/DEMO.md) covers live execution, artifact replay, and the
presentation script.

## Formal results

The frozen plan contained 216 runs. The analysis retained 213 valid records and
3 infrastructure-invalid records; the latter remain visible in the intention-to-
test (ITT) accounting. The table reports valid-run rates across all six tasks.

| Defense | Attack: unauthorized effect | Attack: secret leakage | Clean: benign success |
| --- | ---: | ---: | ---: |
| Allow-All | 9/17 (52.9%) | 6/17 (35.3%) | 17/17 (100%) |
| Prompt-Only | 6/18 (33.3%) | 3/18 (16.7%) | 18/18 (100%) |
| Capability-Only | 3/18 (16.7%) | 3/18 (16.7%) | 17/18 (94.4%) |
| Full | 0/18 (0%) | 0/18 (0%) | 15/18 (83.3%) |

The original T5--T6 comparison showed 3/6 leakages for Capability-Only and 0/6
for Full, but these arms differed in both prompt hierarchy and provenance
checking. The fifth-arm ablation below separates those effects.

### Follow-up ablation result

All 54 Prompt+Capability add-on runs and all 54 Capability+Provenance add-on
runs completed and were valid. In the T5--T6 attack subset:

| Defense | Secret leakage |
| --- | ---: |
| Capability-Only | 3/6 (50.0%) |
| Capability+Provenance | 0/6 (0%) |
| Prompt+Capability | 0/6 (0%) |
| Full | 0/6 (0%) |

Capability+Provenance minus Capability-Only had a paired leakage risk
difference of $-0.50$ (95% bootstrap CI $[-0.83,-0.17]$), as did
Prompt+Capability minus Capability-Only. Full minus Capability+Provenance and
Full minus Prompt+Capability were both $0.00$ (95% bootstrap CI $[0.00,0.00]$).
Thus provenance shows an isolated gain over Capability-Only, while Full has a
floor effect on this corpus and does not add to Prompt+Capability.

The combined analysis covers 324 planned runs: 321 valid and 3
infrastructure-invalid records. Its tables, comparisons, figures, and manifest
are in [`artifacts/provenance-strength-analysis-v1/`](artifacts/provenance-strength-analysis-v1/):

- [results summary](artifacts/provenance-strength-analysis-v1/results_summary.json)
- [publication table](artifacts/provenance-strength-analysis-v1/publication_table.csv)
- [registered comparisons](artifacts/provenance-strength-analysis-v1/registered_comparisons.csv)
- [security figure](artifacts/provenance-strength-analysis-v1/security_outcomes.png)
- [utility figure](artifacts/provenance-strength-analysis-v1/utility_outcomes.png)
- [task-family figure](artifacts/provenance-strength-analysis-v1/task_family_outcomes.png)

The deterministic sink-pressure suite passed 16/16: provenance-enabled arms
denied all 8 protected-value sink calls with zero side effects, while the two
non-provenance controls executed their 8 capability-valid calls. The raw result
is [`artifacts/sink-pressure-v1/results.json`](artifacts/sink-pressure-v1/results.json).

### Independent hardened-corpus follow-up

To test whether Full can add value after the safe prompt, a new Red Agent
system prompt generated a separate 30-candidate corpus using approval-shaped,
compliance-shaped, and data-field/context-laundering strategies. The corpus was
frozen and verified before victim execution. The paired 108-run follow-up (54
Prompt+Capability and 54 Full) had 108/108 valid records:

| Defense | T5--T6 attack leakage | T6 attack leakage |
| --- | ---: | ---: |
| Prompt+Capability | 3/6 (50.0%) | 3/3 (100%) |
| Full | 0/6 (0%) | 0/3 (0%) |

Full minus Prompt+Capability had a paired risk difference of $-0.50$ (95%
bootstrap CI $[-0.83,-0.17]$). This independent hardened set therefore shows
an end-to-end provenance gain that was hidden by the original 0/6 floor. Its
artifacts and figures are in
[`artifacts/hardened-analysis-v1/`](artifacts/hardened-analysis-v1/), with the
frozen corpus in [`data/frozen/red_corpus_qwen3_hardened_v1/`](data/frozen/red_corpus_qwen3_hardened_v1/).
- [technical report PDF](report/main.pdf)

## Demo and report

Launch the replay-safe Gradio app from the controller environment:

```bash
conda run -n test python scripts/demo.py --replay-only
```

Omit `--replay-only` when the local vLLM service and live experiment adapter are
available. The bundled deterministic replay is illustrative only; the formal
claims above come from the frozen Qwen3-VL evaluation and its stored aggregates.
The compiled report is [available here](report/main.pdf).

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
