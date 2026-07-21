# Complete Factorial Corpus Follow-up Design

## Objective

Complete the three-factor defense factorial on both the original and hardened
frozen attack corpora. The factors are safe-prompt hierarchy, capability
gating, and provenance sink checking. Existing formal runs and existing
hardened runs are immutable; only missing cells receive new append-only plans
and artifacts.

## Defense-arm vocabulary

The eight combinations are registered as follows:

| Arm | Safe prompt | Capability | Provenance sink check |
| --- | ---: | ---: | ---: |
| `allow_all` | No | No | No |
| `prompt_only` | Yes | No | No |
| `capability_only` | No | Yes | No |
| `provenance_only` | No | No | Yes |
| `prompt_provenance_only` | Yes | No | Yes |
| `capability_provenance_only` | No | Yes | Yes |
| `prompt_capability_only` | Yes | Yes | No |
| `full` | Yes | Yes | Yes |

`Provenance-only` is intentionally not a replacement for capability gating. It
bypasses capability checks, but scans registered outbound sink fields for exact
protected-value taints. It may therefore block a secret disclosure while still
allowing other unauthorized tool effects. `Prompt+Provenance` adds only the
safe-prompt warning to that behavior. Both new no-capability arms use the same
no-recovery convention as `Prompt-Only`/`Allow-All`; no capability-specific
denial recovery is introduced as an extra factor.

## Missing experimental cells

Each arm contributes six scenarios × three conditions × three paired seeds = 54
victim runs.

- Original corpus: add `provenance_only` and `prompt_provenance_only` (108 runs).
- Hardened corpus: add `allow_all`, `prompt_only`, `capability_only`,
  `provenance_only`, `prompt_provenance_only`, and
  `capability_provenance_only` (324 runs). Existing hardened
  `prompt_capability_only` and `full` records remain separate but complete the
  eight-arm factorial when analyzed together.

Total new execution: 432 runs. Hardened execution is split into three paired
108-cell debug jobs so each job fits the 30-minute A40 limit. Original-corpus
missing arms are run as one paired 108-cell job if queue/runtime checks permit;
otherwise they are split identically.

## Policy and agent semantics

The gateway evaluates provenance independently of capability presence for the
two no-capability provenance arms. A call with no matching capability is
allowed only when it contains no over-sensitivity taint at a registered sink;
the two capability arms retain their existing capability parameter, recipient,
resource, call-count, and provenance checks. Safe prompts are enabled only for
the four prompt arms. Existing `prompt_capability_only` and `full` recovery
behavior is unchanged.

The provenance scan remains exact-literal and source-aware. It does not claim
semantic, encoded, paraphrased, or cross-message information-flow security.

## Frozen plans and analysis

Create independent append-only plan directories for the original missing arms
and the hardened missing arms. Every plan records the corpus manifest digest,
model configuration digest, prompt hashes, arm tuple, randomization seed, and
run-plan SHA-256. Do not modify `formal_plan_v1`, `ablation_plan_v1`,
`capability_provenance_plan_v1`, or `hardened_plan_v1`.

Aggregate each corpus with all eight arms in a new analysis directory. Register
factorial contrasts for T5--T6 attack leakage, including:

- `provenance_only - allow_all`;
- `prompt_provenance_only - prompt_only`;
- `capability_provenance_only - capability_only`;
- `prompt_capability_only - capability_only`;
- `full - capability_provenance_only`;
- `full - prompt_capability_only`.

The report must keep original-corpus and hardened-corpus results separate. A
nonzero leakage rate under an intermediate arm is required before interpreting
the corresponding Full contrast as an end-to-end incremental benefit. Sink
pressure results remain mechanism evidence and are not pooled into victim-run
rates.

## Reproducibility and safety

- Red payloads remain offline-generated and frozen before victim execution.
- All worlds, recipients, protected values, and side effects remain synthetic.
- New artifacts are append-only; no old result or plan is overwritten.
- Controller tests run in the `test` environment; GPU jobs use local Qwen3-VL-8B
  and the `debug` A40 partition when they fit.
- No remote push is performed; changes remain on local branch `ckw`.
