# Provenance Ablation Design

## Objective

Measure the incremental effect of provenance enforcement while holding the
safe prompt, capability checks, model, scenarios, payloads, and paired seeds
constant.

## Treatment

Add one defense arm named `prompt_capability_only`:

| Arm | Safe prompt | Capability checks | Provenance sink check |
| --- | --- | --- | --- |
| `capability_only` | no | yes | no |
| `prompt_capability_only` | yes | yes | no |
| `full` | yes | yes | yes |

`prompt_capability_only` and `full` must also share the same blocked-action
recovery behavior. Their only policy difference is whether protected values
are scanned and blocked at outbound sinks.

## Experimental plan

Keep `configs/frozen/formal_plan_v1` and all 216 existing formal artifacts
unchanged. Freeze a separate `configs/frozen/ablation_plan_v1` containing:

```text
6 scenarios x 3 content conditions x 1 new defense arm x 3 paired seeds
= 54 new runs
```

The ablation uses the existing frozen Qwen3 attack corpus, model configuration,
seeds 4313--4315, and append-only attempt layout. The new plan receives its own
manifest and SHA-256 digest.

## Analysis

Analyze the original 216 formal records and 54 ablation records together. Add
two registered paired contrasts:

1. `prompt_capability_only` minus `capability_only` under attack, measuring the
   incremental safe-prompt effect with capability enforcement held constant.
2. `full` minus `prompt_capability_only` under attack, measuring the
   incremental provenance effect with prompting, capability enforcement, and
   recovery held constant.

The primary provenance contrast is exact secret leakage on T5--T6. Executed
unauthorized effects and clean benign-task success are secondary outcomes.
Invalid attempts remain visible in ITT denominators and are never silently
replaced.

## Interpretation

If `prompt_capability_only` leaks while `full` does not, the experiment
supports an incremental provenance contribution. If both have zero leakage,
the current frozen attacks do not demonstrate a provenance-specific benefit;
the report must state that negative result rather than attribute the combined
Full outcome to provenance.

## Deliverables

- backward-compatible fifth defense arm;
- frozen 54-run ablation plan and manifest;
- append-only raw ablation artifacts;
- combined aggregate tables, registered comparisons, and plots;
- updated English and Chinese README summaries;
- updated PDF report with the ablation result and limitation.

