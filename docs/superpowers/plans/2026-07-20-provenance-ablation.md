# Provenance Ablation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and run a 54-run `prompt_capability_only` ablation that isolates
the incremental provenance effect from safe prompting.

**Architecture:** Extend the defense vocabulary while preserving the original
four-arm formal design as an explicit constant. Freeze the new arm in a
separate plan, execute it with the existing formal runner, and extend analysis
to combine multiple verified plans and artifact roots.

**Tech Stack:** Python 3.11, Pydantic, unittest/pytest, NumPy/Matplotlib,
Slurm, vLLM 0.15.1, Qwen3-VL-8B-Instruct.

## Global Constraints

- Work only on local branch `ckw`; never push to a remote.
- Do not modify or regenerate `configs/frozen/formal_plan_v1`.
- Do not overwrite or retry inside existing `artifacts/formal-v1` attempts.
- `prompt_capability_only` uses the same safe prompt and recovery behavior as
  `full`, capability enforcement enabled, and provenance sink checks disabled.
- Freeze exactly 54 new cells: 6 scenarios x 3 conditions x 1 arm x 3 paired
  seeds.
- Reuse the frozen corpus, model configuration, and seeds 4313--4315.
- Preserve backward compatibility for the old manifest, plan verifier, and
  216-run analysis.
- Keep invalid attempts in ITT accounting; do not silently replace them.

---

### Task 1: Defense-arm semantics

**Files:**
- Modify: `src/agentsec/schemas.py`
- Modify: `src/agentsec/agents.py`
- Modify: `src/agentsec/policy.py`
- Test: `tests/test_policy.py`
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Produces: `DefenseArm.PROMPT_CAPABILITY_ONLY`
- Produces: safe-prompt and recovery behavior shared with `DefenseArm.FULL`
- Preserves: provenance scanning only for `DefenseArm.FULL`

- [ ] **Step 1: Write failing policy and prompt tests**

Add tests asserting that the new arm:

```python
assert DefenseArm.PROMPT_CAPABILITY_ONLY.value == "prompt_capability_only"
assert gateway_for_new_arm_rejects_out_of_manifest_recipient
assert gateway_for_new_arm_allows_registered_secret_without_taint_block
assert UNTRUSTED_DATA_WARNING.strip() in new_arm_system_prompt
```

Add an Action-Agent test showing that a blocked call under the new arm sets the
same recovery continuation as `full`.

- [ ] **Step 2: Verify the tests fail for the missing enum member**

Run:

```bash
conda run -n test pytest tests/test_policy.py tests/test_orchestrator.py -q
```

Expected: failure because `PROMPT_CAPABILITY_ONLY` is not defined.

- [ ] **Step 3: Implement the minimal arm behavior**

Add:

```python
class DefenseArm(str, Enum):
    ALLOW_ALL = "allow_all"
    PROMPT_ONLY = "prompt_only"
    CAPABILITY_ONLY = "capability_only"
    PROMPT_CAPABILITY_ONLY = "prompt_capability_only"
    FULL = "full"
```

Include the new arm in `_system_prompt`'s protected-prompt set and in the
Action-Agent recovery set. Do not include it in the gateway bypass set or the
`DefenseArm.FULL` provenance condition.

- [ ] **Step 4: Verify focused tests pass**

Run the same focused pytest command and require zero failures.

---

### Task 2: Backward-compatible ablation plan

**Files:**
- Modify: `src/agentsec/runplan.py`
- Create: `scripts/freeze_ablation_plan.py`
- Test: `tests/test_runplan.py`

**Interfaces:**
- Produces: `FORMAL_DEFENSE_ARMS`, `ABLATION_DEFENSE_ARMS`
- Produces: `build_ablation_plan(...) -> tuple[RunSpec, ...]`
- Produces: manifests recording `plan_kind` and `defense_arms`
- Preserves: verification of the existing manifest that lacks the new fields

- [ ] **Step 1: Write failing plan tests**

Assert:

```python
assert len(build_formal_plan(scenarios, model)) == 216
assert {r.defense_arm for r in build_formal_plan(...)} == set(FORMAL_DEFENSE_ARMS)
assert len(build_ablation_plan(scenarios, model)) == 54
assert {r.defense_arm for r in build_ablation_plan(...)} == {
    DefenseArm.PROMPT_CAPABILITY_ONLY
}
```

Freeze and verify a temporary ablation plan, then verify the checked-in old
formal plan remains valid.

- [ ] **Step 2: Run tests and observe the missing API failure**

```bash
conda run -n test pytest tests/test_runplan.py -q
```

- [ ] **Step 3: Implement explicit arm sets and manifest compatibility**

Use explicit tuples rather than `tuple(DefenseArm)`:

```python
FORMAL_DEFENSE_ARMS = (
    DefenseArm.ALLOW_ALL,
    DefenseArm.PROMPT_ONLY,
    DefenseArm.CAPABILITY_ONLY,
    DefenseArm.FULL,
)
ABLATION_DEFENSE_ARMS = (DefenseArm.PROMPT_CAPABILITY_ONLY,)
```

Make manifest fields default to the old formal values so the existing JSON
remains valid. Parameterize plan validation by manifest arm set and derive the
expected record count from scenarios, conditions, arms, and seeds.

- [ ] **Step 4: Add the dedicated freeze CLI and verify tests**

`scripts/freeze_ablation_plan.py` must hash the same model, prompt, scenario,
and corpus inputs as the formal freezer, but call `build_ablation_plan` and
write `plan_kind="provenance_ablation"`.

---

### Task 3: Combined registered analysis

**Files:**
- Modify: `src/agentsec/analysis.py`
- Modify: `scripts/analyze_results.py`
- Test: `tests/test_analysis.py`

**Interfaces:**
- Consumes: one or more artifact roots and one or more verified plan dirs
- Produces: existing 13 comparisons for old-only inputs
- Produces: additional safe-prompt and provenance ablation comparisons when
  `prompt_capability_only` records are present

- [ ] **Step 1: Write failing multi-root and contrast tests**

Create paired fixture records for `capability_only`,
`prompt_capability_only`, and `full`. Assert:

```python
names = {item.name for item in registered_comparisons(rows)}
assert "a1_prompt_capability_minus_capability_attack_leakage__provenance_t5_t6" in names
assert "a2_full_minus_prompt_capability_attack_leakage__provenance_t5_t6" in names
```

Assert old-only inputs still produce exactly 13 comparisons. Add a multi-root
analysis test proving both verified record sets are included without duplicate
selection.

- [ ] **Step 2: Run focused analysis tests and observe failure**

```bash
conda run -n test pytest tests/test_analysis.py -q
```

- [ ] **Step 3: Implement multi-root loading and conditional contrasts**

Keep the single-root API compatible. Combine roots deterministically, reject
duplicate run IDs across roots, and validate against the concatenated verified
plans. Add ablation contrasts only when the new arm is present.

- [ ] **Step 4: Make publication tables and plots support five arms**

Use a label mapping keyed by defense value:

```python
DEFENSE_LABELS = {
    "allow_all": "Allow all",
    "prompt_only": "Prompt only",
    "capability_only": "Capability",
    "prompt_capability_only": "Prompt + capability",
    "full": "Full",
}
```

Require focused tests and plot generation to pass.

---

### Task 4: Cluster runner and documentation

**Files:**
- Create: `scripts/run_ablation.slurm`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/EXPERIMENT_PROTOCOL.md`
- Modify: `README.md`
- Modify: `README_ZH.md`
- Modify: `src/agentsec/demo.py`
- Test: `tests/test_demo.py`

**Interfaces:**
- Consumes: `configs/frozen/ablation_plan_v1`
- Writes: `artifacts/ablation-v1`
- Writes: `artifacts/ablation-analysis-v1`

- [ ] **Step 1: Add a failing demo-choice test**

Assert the new arm appears in the demo defense choices with a readable label.

- [ ] **Step 2: Add the Slurm job**

Start one local vLLM server, run only the 54 ablation cells, and analyze:

```bash
python scripts/analyze_results.py \
  --artifact-root artifacts/formal-v1 \
  --artifact-root artifacts/ablation-v1 \
  --plan-dir configs/frozen/formal_plan_v1 \
  --plan-dir configs/frozen/ablation_plan_v1 \
  --output-dir artifacts/ablation-analysis-v1
```

The job must use append-only output directories and exit nonzero on invalid
records while retaining their artifacts.

- [ ] **Step 3: Update concise documentation**

Describe the fifth arm and the 54-run add-on without rewriting the old
216-run result as a 270-run preregistered study. Mark ablation result fields as
pending until aggregation succeeds.

- [ ] **Step 4: Verify the complete unit suite**

```bash
bash scripts/run_tests.sh
```

---

### Task 5: Freeze, execute, aggregate, and report

**Files:**
- Create: `configs/frozen/ablation_plan_v1/manifest.json`
- Create: `configs/frozen/ablation_plan_v1/run_plan.jsonl`
- Create: `artifacts/ablation-analysis-v1/*`
- Modify: `report/generated/results_summary.tex`
- Modify: `report/main.tex`
- Modify: `README.md`
- Modify: `README_ZH.md`
- Update: `report/main.pdf`

**Interfaces:**
- Produces: immutable plan hash and 54 append-only attempts
- Produces: combined 270-record aggregate with invalid counts visible

- [ ] **Step 1: Freeze and verify the plan**

```bash
conda run -n test python scripts/freeze_ablation_plan.py \
  --corpus-dir data/frozen/red_corpus_qwen3_v1 \
  --output-dir configs/frozen/ablation_plan_v1
```

Verify the plan contains exactly 54 unique cells and only the new arm.

- [ ] **Step 2: Submit and follow the Slurm job**

```bash
sbatch scripts/run_ablation.slurm
```

Monitor until terminal state. Do not overwrite existing attempts.

- [ ] **Step 3: Interpret the registered provenance contrast**

Report both valid-only and ITT results for:

```text
full minus prompt_capability_only
metric: secret_leakage
family: T5--T6
condition: attack
```

- [ ] **Step 4: Update report and README with observed data**

State a provenance-specific benefit only if the paired contrast supports it.
Otherwise state that the frozen corpus does not isolate an incremental
provenance benefit.

- [ ] **Step 5: Compile and verify final deliverables**

```bash
bash scripts/compile_report.sh
bash scripts/run_tests.sh
git diff --check
```

Confirm the PDF exists, all aggregate links resolve, and no remote push
occurred.

