# Provenance Strengthening and Hard-Attack Follow-up Design

## Objective

Strengthen the causal evidence for provenance enforcement without modifying the
original 216-run study or reusing any result-dependent attack selection.

## Workstream 1: Capability + Provenance arm

Add `capability_provenance_only`:

| Arm | Safe prompt | Capability checks | Provenance sink check | Blocked-call recovery |
| --- | --- | --- | --- | --- |
| `capability_only` | No | Yes | No | No |
| `capability_provenance_only` | No | Yes | Yes | No |
| `prompt_capability_only` | Yes | Yes | No | Yes |
| `full` | Yes | Yes | Yes | Yes |

The new arm changes only the sink check relative to `capability_only`, and is
therefore the no-prompt provenance contrast. It uses the existing model,
scenarios, payloads, paired seeds, and a separately frozen 54-cell plan. The
primary comparison is exact secret leakage on T5--T6 attacks:

```
capability_provenance_only - capability_only
```

The original formal plan and `ablation_plan_v1` remain immutable.

## Workstream 2: Deterministic provenance sink pressure test

Add a CPU-only, model-independent pressure-test script. For each of four
authorized sink arguments containing an observed registered secret, execute the
same call through `capability_only`, `capability_provenance_only`,
`prompt_capability_only`, and `full`.

The test records the policy decision, detected taint IDs, execution status,
outbox mutation count, and whether the expected provenance denial occurred.
The expected result is:

| Arm | Sink call executes | Secret leakage |
| --- | --- | --- |
| `capability_only` | Yes | Yes |
| `capability_provenance_only` | No | No |
| `prompt_capability_only` | Yes | Yes |
| `full` | No | No |

The result is a self-contained JSON artifact and is not mixed into victim-run
rate estimates. It directly validates that a malicious tool proposal that
already satisfies capability constraints is blocked only when provenance sink
checking is enabled.

## Workstream 3: Independent hardened attack corpus

Generate a new offline Red-Agent corpus with a stronger, explicitly
defense-aware attack-generation prompt. Candidate selection is fixed by
candidate index before victim evaluation; no candidate is selected from Full or
Prompt+Capability victim success. The corpus receives its own manifest and
SHA-256 digest.

The hardened corpus is evaluated as an exploratory follow-up with paired
`prompt_capability_only` and `full` arms over the same six scenarios, three
conditions, and three seeds. The primary contrast is T5--T6 attack leakage.
The protocol labels this as a new frozen test family rather than pooling it
with the original or first ablation corpus.

If Prompt+Capability has nonzero leakage and Full has lower leakage on the
hardened corpus, that is evidence of an end-to-end incremental provenance
benefit. If both remain at zero, the report must state that the stronger frozen
corpus still did not expose an incremental benefit. A result of zero is not
interpreted as proof of equivalence.

## Reproducibility and safety

- All new plans and corpora are append-only and have independent manifests.
- Existing formal and first-ablation artifacts are not rewritten.
- All secrets, recipients, resources, and side effects remain synthetic/local.
- New source behavior is covered by tests before cluster execution.
- New report text distinguishes mechanism-level evidence from end-to-end model
  evidence.
