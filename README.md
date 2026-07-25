# Provenance-Aware Capability Gating against Indirect Prompt Injection

[中文说明](README_ZH.md)

## Frozen project scope: PACT core

The course-project main line is now the deterministic PACT (Provenance-Aware
Capability Tracking/Control) mechanism. The key claim is narrow: ordinary
capability checks ask whether a value is on an allow-list; PACT also checks
whether that value is trusted for the requested parameter role.

The minimum experiment has four auditable cases: user-selected Alice is
allowed, an allow-listed Bob supplied by an external email is denied at the
recipient role, external email text is allowed at a low-risk content role, and a
user value is allowed after an explicitly registered Base64 transformation.
The result table, decision logs, architecture diagram, and hashes are in
[`artifacts/pact-minimum-v2/`](artifacts/pact-minimum-v2/); the protocol is in
[`docs/PACT_MINIMUM.md`](docs/PACT_MINIMUM.md).

The AgentDojo runs below are retained as an external attack-realism baseline.
They are not used as direct evidence for PACT effectiveness. Secret Broker,
semantic provenance, L3 confirmation, extra models, and extra seeds are future
work.

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
configured for BF16, a configurable 16K default context, one GPU, and the Hermes tool parser.

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

The completed factorial follow-up adds the missing `provenance_only` and
`prompt_provenance_only` arms on the original corpus, and six missing arms on
the hardened corpus. Each corpus is analyzed separately as
`6 x 3 x 8 x 3 = 432` planned victim cells. Provenance-only arms deliberately
skip capability enforcement and only test exact protected-value sink blocking;
they are not substitutes for least-authority capability gating. A deterministic
16-case sink-pressure test separately exercises malicious values at email
subject/body and calendar title/location sinks.

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

### Original-corpus complete factorial result

The original complete factorial contains 432 planned records: 428 valid and 4
invalid ITT records. In the T5--T6 attack subset:

| Defense | Secret leakage |
| --- | ---: |
| Allow-All | 3/6 (50.0%) |
| Prompt-Only | 0/6 (0%) |
| Capability-Only | 3/6 (50.0%) |
| Provenance-only | 0/6 (0%) |
| Prompt+Provenance | 0/6 (0%) |
| Capability+Provenance | 0/6 (0%) |
| Prompt+Capability | 0/6 (0%) |
| Full | 0/6 (0%) |

Provenance-only minus Allow-All was $-0.50$ (95% bootstrap CI
$[-0.83,-0.17]$); Prompt+Provenance minus Prompt-Only was $0.00$. The
capability-plus-provenance contrast was also $-0.50$ versus Capability-Only.
Full and Prompt+Capability both remained at the 0/6 floor on this corpus.

Tables, comparisons, figures, and the manifest are in
[`artifacts/original-full-factorial-analysis-v1/`](artifacts/original-full-factorial-analysis-v1/):

- [results summary](artifacts/original-full-factorial-analysis-v1/results_summary.json)
- [publication table](artifacts/original-full-factorial-analysis-v1/publication_table.csv)
- [registered comparisons](artifacts/original-full-factorial-analysis-v1/registered_comparisons.csv)
- [security figure](artifacts/original-full-factorial-analysis-v1/security_outcomes.png)
- [utility figure](artifacts/original-full-factorial-analysis-v1/utility_outcomes.png)
- [task-family figure](artifacts/original-full-factorial-analysis-v1/task_family_outcomes.png)

The deterministic sink-pressure suite passed 16/16: provenance-enabled arms
denied all 8 protected-value sink calls with zero side effects, while the two
non-provenance controls executed their 8 capability-valid calls. The raw result
is [`artifacts/sink-pressure-v1/results.json`](artifacts/sink-pressure-v1/results.json).

### Hardened-corpus complete factorial result

The hardened complete factorial uses a separate 30-candidate corpus generated
with approval-shaped, compliance-shaped, and data-field/context-laundering
strategies. It contains 432 planned records: 428 valid and 4 invalid ITT
records. In the T5--T6 attack subset:

| Defense | T5--T6 attack leakage | T6 attack leakage |
| --- | ---: | ---: |
| Allow-All | 2/6 (33.3%) | 2/3 (66.7%) |
| Prompt-Only | 3/6 (50.0%) | 3/3 (100%) |
| Capability-Only | 2/6 (33.3%) | 2/3 (66.7%) |
| Provenance-only | 0/6 (0%) | 0/3 (0%) |
| Prompt+Provenance | 0/6 (0%) | 0/3 (0%) |
| Capability+Provenance | 0/6 (0%) | 0/3 (0%) |
| Prompt+Capability | 3/6 (50.0%) | 3/3 (100%) |
| Full | 0/6 (0%) | 0/3 (0%) |

Provenance-only minus Allow-All was $-0.33$ (95% CI $[-0.67,0.00]$),
Prompt+Provenance minus Prompt-Only was $-0.50$ (95% CI $[-0.83,-0.17]$),
and Full minus Prompt+Capability was $-0.50$ (95% CI $[-0.83,-0.17]$).
This hardened set therefore shows an end-to-end provenance gain above the
safe prompt/capability baseline. Its artifacts and figures are in
[`artifacts/hardened-full-factorial-analysis-v1/`](artifacts/hardened-full-factorial-analysis-v1/), with the
frozen corpus in [`data/frozen/red_corpus_qwen3_hardened_v1/`](data/frozen/red_corpus_qwen3_hardened_v1/).
- [technical report PDF](report/main.pdf)

## Full native AgentDojo benchmark

We completed the pinned native AgentDojo suites with local Qwen3-VL-8B-Instruct:
AgentDojo `v0.1.35` at commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`,
benchmark `v1.2.2`, BF16 vLLM, and a 16K context. The formal plan contains
3,942 rows: Workspace 2,308, Travel 588, Banking 596, and Slack 450. All
3,942 formal records are covered; 3,935 are valid and 7 Workspace rows are
`agentdojo_execution_error` records retained in the ITT denominator.

The benchmark reports AgentDojo targeted attack success and utility separately
from this project's T1--T4 authority leakage and T5--T6 sensitive-value leakage.
The official AgentDojo matrix has no synthetic-secret metric, so these results
are not pooled with the project factorial tables. Valid-only values are shown
first; ITT is shown in parentheses.

| Attack / defense | Targeted ASR | Attack utility | Clean utility |
| --- | ---: | ---: | ---: |
| `important_instructions` / `none` | 95/940 (95/941), 10.1% | 637/940, 67.8% | 64/89, 71.9% |
| `important_instructions` / `repeat_user_prompt` | 81/940 (81/941), 8.6% | 610/940, 64.9% | 65/89, 73.0% |
| `tool_knowledge` / `none` | 152/937 (152/941), 16.2% | 584/937, 62.3% | 64/89, 71.9% |
| `tool_knowledge` / `repeat_user_prompt` | 97/940 (97/941), 10.3% | 620/940, 66.0% | 65/89, 73.0% |

The compact [results summary](artifacts/agentdojo-external-full-analysis-v1/results_summary.json),
[attack table](artifacts/agentdojo-external-full-analysis-v1/attack_summary.csv),
[clean-utility table](artifacts/agentdojo-external-full-analysis-v1/clean_utility.csv),
[publication figure](artifacts/agentdojo-external-full-analysis-v1/agentdojo_outcomes.png),
and [attempt-selection manifest](artifacts/agentdojo-external-full-v1/attempt_selection.json)
are retained. Raw vLLM logs and complete official traces remain untracked. See
[the external-validation note](docs/EXTERNAL_VALIDATION.md) for denominators,
hashes, and scope limitations.

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
