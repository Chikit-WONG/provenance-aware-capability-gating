# Complete Factorial Corpus Follow-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the registered provenance ablations on both the original and hardened frozen attack corpora, then produce separate full-factorial analyses that quantify whether provenance adds end-to-end protection beyond prompts and capabilities.

**Architecture:** Add two explicit defense arms (`provenance_only` and `prompt_provenance_only`) to the policy and prompt layers. Freeze one 108-cell original completion plan and three 108-cell hardened completion plans (paired arms so each fits the 30-minute debug queue), run them against the existing frozen corpora without changing prior plans, and combine artifact roots only within the same corpus for analysis. Extend the registered comparison registry with provenance-specific factorial contrasts while preserving the old comparison outputs for old-only artifact sets.

**Tech Stack:** Python 3, Pydantic schemas, `unittest`, JSONL frozen manifests, existing vLLM/SLURM runners, matplotlib/report LaTeX tooling.

## Global Constraints

- Work only on the local `ckw` branch; do not push to `origin/ckw`.
- Do not modify or regenerate `configs/frozen/formal_plan_v1`, `ablation_plan_v1`, `capability_provenance_plan_v1`, or `hardened_plan_v1`.
- Use the frozen offline attack corpora `data/frozen/red_corpus_qwen3_v1` and `data/frozen/red_corpus_qwen3_hardened_v1`; no new attack generation is allowed for this follow-up.
- The new no-capability provenance arms scan registered outbound sink fields and block tainted values above `Sensitivity.PUBLIC`; they do not enforce capabilities or recovery continuations.
- Use `/hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python` with `PYTHONPATH=src` for tests and runners.
- Prefer SLURM `debug` with `--gres=gpu:a40:1` for each 108-cell job; use the existing model cache and do not download another model.
- Every new plan and result directory is append-only and must be hash-verified before analysis.

## File Map

- Modify `src/agentsec/schemas.py`: register the two new enum values.
- Modify `src/agentsec/policy.py`: implement provenance sink checks for no-capability arms while preserving existing capability and Full behavior.
- Modify `src/agentsec/agents.py`: include `prompt_provenance_only` in the safe system-prompt arms; leave recovery behavior unchanged for the new arms.
- Modify `src/agentsec/runplan.py`: add builders and manifest validation for the original completion plan and three hardened paired completion plans.
- Modify `src/agentsec/analysis.py`: add labels and conditional provenance-factorial comparisons without changing old-only comparison counts.
- Modify `tests/test_policy.py`, `tests/test_orchestrator.py`, `tests/test_runplan.py`, and `tests/test_analysis.py`: lock the new semantics and plan/analysis contracts.
- Create `scripts/freeze_original_provenance_completion.py`: freeze the 108-cell original-corpus completion plan.
- Create `scripts/freeze_hardened_missing_plans.py`: freeze three immutable 108-cell hardened completion plans.
- Create `scripts/run_original_provenance_completion.slurm`: run the original completion plan on the cached model.
- Create `scripts/run_hardened_missing.slurm`: parameterized runner for one hardened paired plan selected by `HARDENED_GROUP`.
- Create `scripts/analyze_complete_factorial.py`: verify and combine corpus-specific artifact roots and call the existing analyzer.
- Later modify `README.md`, `README.zh-CN.md`, `report/main.tex`, and generated `report/main.pdf` only after all jobs and analyses are verified.

---

### Task 1: Add and test the two provenance-only defense arms

**Files:**
- Modify: `src/agentsec/schemas.py:32-45`
- Modify: `src/agentsec/policy.py:175-330`
- Modify: `src/agentsec/agents.py` system-prompt arm selection
- Test: `tests/test_policy.py`, `tests/test_orchestrator.py`

**Interfaces:**
- Produces enum values `DefenseArm.PROVENANCE_ONLY` and `DefenseArm.PROMPT_PROVENANCE_ONLY`.
- `CapabilityGateway.evaluate()` allows untainted/public outbound sink calls for these arms and denies exact taints whose sensitivity rank is above `Sensitivity.PUBLIC`, even when no capability grants the tool.
- `_system_prompt()` treats `PROMPT_PROVENANCE_ONLY` as a safe-prompt arm; recovery continuation remains enabled only for `PROMPT_CAPABILITY_ONLY` and `FULL`.

- [ ] **Step 1: Write failing policy tests.** Add tests that construct a gateway with no capabilities and assert that a public `send_email` is allowed under both new arms, while a protected secret token in `body` is denied with the protected ID in `reason` and `detected_taints`.

```python
def test_provenance_only_blocks_secret_without_capability():
    _, _, _, executor, gateway = make_stack(DefenseArm.PROVENANCE_ONLY, ())
    gateway.taint_tracker.register(
        ProtectedValue(
            protected_id="secret-token",
            value="TOKEN-123",
            sensitivity=Sensitivity.SECRET,
            source_resource_id="file-1",
        )
    )
    result = gateway.execute(
        executor,
        ToolName.SEND_EMAIL,
        {"to": "external@example.com", "subject": "x", "body": "TOKEN-123"},
    )
    self.assertFalse(result.decision.allowed)
    self.assertIn("secret-token", result.decision.reason)
    self.assertEqual(result.decision.detected_taints[0].protected_id, "secret-token")

def test_prompt_provenance_allows_public_sink_without_capability():
    _, _, _, executor, gateway = make_stack(DefenseArm.PROMPT_PROVENANCE_ONLY, ())
    result = gateway.execute(
        executor,
        ToolName.SEND_EMAIL,
        {"to": "external@example.com", "subject": "x", "body": "public text"},
    )
    self.assertTrue(result.decision.allowed)
```

- [ ] **Step 2: Run the focused tests and confirm they fail before implementation.**

Run: `PYTHONPATH=src:tests /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_policy -q`

Expected: FAIL because the enum members and no-capability provenance branch do not yet exist.

- [ ] **Step 3: Implement the minimal policy and prompt changes.** Add the enum values, add `PROMPT_PROVENANCE_ONLY` to the safe-prompt selection, and refactor sink scanning into a helper that accepts a maximum sensitivity. In `evaluate()`, keep `ALLOW_ALL`/`PROMPT_ONLY` as unconditional bypasses, then handle the two provenance-only arms before capability lookup:

```python
if self.defense_arm in (DefenseArm.PROVENANCE_ONLY, DefenseArm.PROMPT_PROVENANCE_ONLY):
    taints = self._provenance_violations(
        tool_name, arguments, Sensitivity.PUBLIC
    )
    if taints:
        identifiers = ", ".join(taint.protected_id for taint in taints)
        return self._record_decision(
            actor=actor, tool=tool_name, arguments=arguments,
            proposal_event_id=proposal.event_id, allowed=False,
            reason=f"protected values exceed maximum outbound sensitivity public: {identifiers}",
            taints=taints,
        )
    return self._record_decision(
        actor=actor, tool=tool_name, arguments=arguments,
        proposal_event_id=proposal.event_id, allowed=True,
        reason=f"{self.defense_arm.value} provenance checks passed",
        taints=(),
    )
```

The helper must return only taints above its supplied sensitivity and must scan only `_SINK_FIELDS`; existing capability arms must continue to use their capability-specific maximum. Do not add recovery state for either new arm.

- [ ] **Step 4: Run policy and orchestrator tests.**

Run: `PYTHONPATH=src:tests /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_policy tests.test_orchestrator -q`

Expected: PASS, including all pre-existing capability, Full, and recovery tests.

- [ ] **Step 5: Commit the semantic change.**

```bash
git add src/agentsec/schemas.py src/agentsec/policy.py src/agentsec/agents.py tests/test_policy.py tests/test_orchestrator.py
git commit -m "feat: add provenance-only defense arms"
```

### Task 2: Extend frozen run-plan builders and freeze the four completion plans

**Files:**
- Modify: `src/agentsec/runplan.py`
- Test: `tests/test_runplan.py`
- Create: `scripts/freeze_original_provenance_completion.py`
- Create: `scripts/freeze_hardened_missing_plans.py`

**Interfaces:**
- Produces `build_original_provenance_completion_plan(...)` with arms `(PROVENANCE_ONLY, PROMPT_PROVENANCE_ONLY)` and 108 records.
- Produces `build_hardened_missing_plan(..., defense_arms=...)` for exactly one of three paired tuples: `(ALLOW_ALL, PROMPT_ONLY)`, `(CAPABILITY_ONLY, CAPABILITY_PROVENANCE_ONLY)`, `(PROVENANCE_ONLY, PROMPT_PROVENANCE_ONLY)`; each returns 108 records.
- `FrozenRunPlanManifest.plan_kind` accepts `original_provenance_completion`, `hardened_missing_baseline`, `hardened_missing_capability`, and `hardened_missing_provenance_prompt`, with exact arm validation.

- [ ] **Step 1: Add failing builder and manifest tests.** Extend `tests/test_runplan.py` to assert the new builders produce 108 unique cells, expected arm tuples, and deterministic SHA-256 manifests; assert that a mismatched new `plan_kind`/arm tuple raises `ValidationError`.

```python
def test_completion_builders_have_registered_cell_counts():
    original = build_original_provenance_completion_plan(SCENARIOS, MODEL_CONFIG)
    self.assertEqual(len(original), 108)
    self.assertEqual({row.defense_arm for row in original}, {
        DefenseArm.PROVENANCE_ONLY, DefenseArm.PROMPT_PROVENANCE_ONLY
    })
    hardened = build_hardened_missing_plan(
        SCENARIOS, MODEL_CONFIG,
        defense_arms=(DefenseArm.ALLOW_ALL, DefenseArm.PROMPT_ONLY),
    )
    self.assertEqual(len(hardened), 108)
```

- [ ] **Step 2: Run the focused run-plan tests and confirm the new tests fail.**

Run: `PYTHONPATH=src:tests /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_runplan -q`

Expected: FAIL with missing builder/manifest support.

- [ ] **Step 3: Implement new constants, plan-kind validation, and builders.** Keep existing builders byte-for-byte semantically compatible. Add explicit mappings for the three hardened paired plan kinds instead of accepting arbitrary arm tuples in a manifest. Reuse `_build_plan` and `freeze_formal_plan`; update `__all__`.

- [ ] **Step 4: Implement the original freeze script.** It must load the original corpus manifest and scenario JSON, use the existing model-config and prompt inputs from `configs/frozen/formal_plan_v1`, assert all input hashes, call `build_original_provenance_completion_plan`, and create `configs/frozen/original_provenance_completion_v1` only if absent. It must print the manifest hash and record count.

- [ ] **Step 5: Implement the hardened freeze script.** It must load the hardened corpus and the same frozen model/prompt inputs used by `configs/frozen/hardened_plan_v1`, then create exactly these directories with their corresponding paired arms:

```text
configs/frozen/hardened_missing_baseline_v1/
configs/frozen/hardened_missing_capability_v1/
configs/frozen/hardened_missing_provenance_prompt_v1/
```

Each directory must be created with `exist_ok=False`, record its corpus/input SHA-256 values, and print `record_count=108`.

- [ ] **Step 6: Run the builders, freeze scripts, and tests.**

Run:

```bash
PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_runplan -q
PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python scripts/freeze_original_provenance_completion.py
PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python scripts/freeze_hardened_missing_plans.py
PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -c "from agentsec.runplan import verify_frozen_plan; [print(verify_frozen_plan(p)[0].record_count) for p in ['configs/frozen/original_provenance_completion_v1','configs/frozen/hardened_missing_baseline_v1','configs/frozen/hardened_missing_capability_v1','configs/frozen/hardened_missing_provenance_prompt_v1']]"
```

Expected: focused tests pass and the final command prints `108` four times; rerunning either freeze script must fail rather than rewrite an existing plan.

- [ ] **Step 7: Commit the frozen-plan implementation.**

```bash
git add src/agentsec/runplan.py tests/test_runplan.py scripts/freeze_original_provenance_completion.py scripts/freeze_hardened_missing_plans.py configs/frozen/original_provenance_completion_v1 configs/frozen/hardened_missing_baseline_v1 configs/frozen/hardened_missing_capability_v1 configs/frozen/hardened_missing_provenance_prompt_v1
git commit -m "feat: freeze provenance completion plans"
```

### Task 3: Add SLURM runners for the original and hardened completion cells

**Files:**
- Create: `scripts/run_original_provenance_completion.slurm`
- Create: `scripts/run_hardened_missing.slurm`
- Test: shell syntax and dry-run validation commands

**Interfaces:**
- `run_original_provenance_completion.slurm` runs `configs/frozen/original_provenance_completion_v1` into `artifacts/original-provenance-completion-v1`.
- `run_hardened_missing.slurm` accepts `HARDENED_GROUP` in `{baseline,capability,provenance_prompt}` and maps to the matching plan/output directory.

- [ ] **Step 1: Add runner validation checks before model startup.** Both scripts must use `#SBATCH --partition=debug`, `#SBATCH --gres=gpu:a40:1`, `#SBATCH --time=00:30:00`, `set -euo pipefail`, offline Hugging Face variables, and verify the plan, corpus, model path, and pilot report before launching vLLM. The scripts must call the existing runner with `--append-only` and must not regenerate attack data.

- [ ] **Step 2: Add a shell-level dry-run guard.** Use `bash -n` and a local invalid-group invocation that exits with a clear error before any GPU/model startup.

```bash
bash -n scripts/run_original_provenance_completion.slurm scripts/run_hardened_missing.slurm
HARDENED_GROUP=unknown bash scripts/run_hardened_missing.slurm
```

Expected: syntax check succeeds; invalid group exits nonzero and reports the allowed group names.

- [ ] **Step 3: Commit the runners.**

```bash
git add scripts/run_original_provenance_completion.slurm scripts/run_hardened_missing.slurm
git commit -m "ops: add completion experiment runners"
```

- [ ] **Step 4: Check queue and submit four jobs without pushing.** First run the repository queue check, then submit one original job and the three hardened group jobs. Capture job IDs in `artifacts/completion-job-ids.txt` and do not submit duplicate jobs if a matching job is already running or its artifact root is complete.

```bash
for p in debug i64m1tga40u emergency_gpua40 i64m1tga800u emergency_gpu i64m512u a128m512u; do
  printf '%-22s pending=%-3s running=%-3s\n' "$p" \
    "$(squeue -h -p "$p" -t PENDING | wc -l)" \
    "$(squeue -h -p "$p" -t RUNNING | wc -l)"
done
sbatch scripts/run_original_provenance_completion.slurm
HARDENED_GROUP=baseline sbatch scripts/run_hardened_missing.slurm
HARDENED_GROUP=capability sbatch scripts/run_hardened_missing.slurm
HARDENED_GROUP=provenance_prompt sbatch scripts/run_hardened_missing.slurm
```

### Task 4: Extend analysis with registered provenance contrasts

**Files:**
- Modify: `src/agentsec/analysis.py:28-45,194-275`
- Test: `tests/test_analysis.py`
- Create: `scripts/analyze_complete_factorial.py`

**Interfaces:**
- Adds labels for the two new arms.
- When all relevant arms are present, `registered_comparisons()` adds these stable names:

```text
a5_provenance_only_minus_allow_all_attack_leakage__provenance_t5_t6
a6_prompt_provenance_minus_prompt_only_attack_leakage__provenance_t5_t6
a7_full_minus_prompt_provenance_attack_leakage__provenance_t5_t6
a8_full_minus_provenance_only_attack_leakage__provenance_t5_t6
```

- `scripts/analyze_complete_factorial.py` verifies all four original/hardened plan manifests, combines only same-corpus roots, and writes `artifacts/original-full-factorial-analysis-v1` and `artifacts/hardened-full-factorial-analysis-v1`.

- [ ] **Step 1: Write failing analysis tests.** Build synthetic rows containing all eight arms and assert the four new comparison names exist and have deterministic estimates. Also assert the existing old-only synthetic fixture keeps its previous comparison count and names.

- [ ] **Step 2: Run focused analysis tests and confirm the new assertions fail.**

Run: `PYTHONPATH=src:tests /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_analysis -q`

Expected: FAIL only on the new labels/comparisons.

- [ ] **Step 3: Implement conditional labels and comparisons.** Preserve `DEFENSE_ORDER` compatibility for old plots, add the two labels, and append the new comparisons only when their selector arms are present. Use the existing paired bootstrap/statistics implementation and the exact selectors `(ContentCondition.ATTACK, scenario_ids T5/T6, defense arms listed above)`.

- [ ] **Step 4: Implement corpus-specific analysis orchestration.** The script must pass each plan directory to the existing plan-aware loader, reject missing/invalid records, combine original roots (formal, provenance ablation, capability-provenance ablation, original completion), combine hardened roots (hardened follow-up plus three hardened completion roots), and call the existing `analyze_runs`/artifact writer without cross-corpus pooling.

- [ ] **Step 5: Run analysis tests and syntax checks.**

Run:

```bash
PYTHONPATH=src:tests /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_analysis -q
PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m py_compile src/agentsec/analysis.py scripts/analyze_complete_factorial.py
```

Expected: PASS and no compile errors.

- [ ] **Step 6: Commit analysis changes.**

```bash
git add src/agentsec/analysis.py tests/test_analysis.py scripts/analyze_complete_factorial.py
git commit -m "feat: analyze complete factorial defenses"
```

### Task 5: Verify all artifacts, regenerate report/README, and document results

**Files:**
- Modify: `README.md`, `README.zh-CN.md`, `report/main.tex`
- Regenerate: `report/main.pdf`, `report/figures/*`, `artifacts/original-full-factorial-analysis-v1/*`, `artifacts/hardened-full-factorial-analysis-v1/*`
- Test: complete test suite and artifact integrity checks

**Interfaces:**
- Produces separate original/hardened tables and figures with all eight arms, the four new contrasts, cell counts, leakage rates, and confidence intervals.
- README English/Chinese remain concise and state clearly whether provenance adds incremental benefit over Prompt+Capability on each corpus; they must distinguish a null result from a positive sink-pressure result.

- [ ] **Step 1: Wait for all four jobs and inspect logs.** Poll `squeue`, then verify each artifact root contains 108 valid result records, no duplicate run IDs, and manifest hashes match their frozen plans.

- [ ] **Step 2: Run the complete-factorial analysis script.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python scripts/analyze_complete_factorial.py`

Expected: both output directories are created with `summary.json`, `registered_comparisons.json`, CSV tables, and figures; original and hardened record counts are reported separately.

- [ ] **Step 3: Regenerate the report with the TinyTeX compiler.** Update report inputs from the two new analysis summaries, keep the negative/positive provenance conclusions numerically grounded, and compile with:

```bash
export PATH=/hpc2hdd/home/ckwong627/.TinyTeX/bin/x86_64-linux:$PATH
cd report
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
test -s main.pdf
```

- [ ] **Step 4: Update both READMEs concisely.** Add links to the original/hardened complete-factorial summaries, one compact table per corpus, and a short interpretation of the new provenance-only and Prompt+Provenance arms. Do not claim provenance-only blocks unauthorized actions that it does not check; describe it as a sink-taint guard.

- [ ] **Step 5: Run the full verification suite.**

Run:

```bash
PYTHONPATH=src:tests /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest discover -s tests -q
git diff --check
git status --short --branch
```

Expected: all tests pass, no whitespace errors, branch remains `ckw` and has no remote push performed. If a final LaTeX pass returns nonzero only because of `rerunfilecheck` while `report/main.pdf` exists, retain the valid PDF and record that non-fatal warning.

- [ ] **Step 6: Commit verified artifacts and documentation.**

```bash
git add README.md README.zh-CN.md report artifacts/original-full-factorial-analysis-v1 artifacts/hardened-full-factorial-analysis-v1
git commit -m "docs: publish complete factorial ablation results"
```

