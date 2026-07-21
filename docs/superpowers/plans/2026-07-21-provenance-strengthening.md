# Provenance Strengthening and Hard-Attack Follow-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a no-prompt provenance arm, a deterministic sink pressure test, and an independently frozen hardened attack corpus with paired Full versus Prompt+Capability evaluation.

**Architecture:** Extend the existing DefenseArm and frozen-plan abstractions with a separate 54-cell capability-plus-provenance plan. Keep the sink pressure test as a deterministic policy-level script. Reuse the existing offline Red-Agent generator with a new hardened system prompt and independent corpus/plan directories, then use the existing append-only runner and combined analysis with explicit family labels.

**Tech Stack:** Python 3.10, Pydantic, unittest, existing Qwen3-VL-8B-Instruct/vLLM service, SLURM A40 debug partition, JSON/JSONL/CSV artifacts.

## Global Constraints

- Do not alter `configs/frozen/formal_plan_v1` or `configs/frozen/ablation_plan_v1`.
- Do not select hardened payloads using victim Full or Prompt+Capability success.
- Keep all resources, secrets, recipients, and side effects synthetic and local.
- Use `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest discover -s tests -q` for controller tests.
- Prefer the `debug` SLURM partition with `--gres=gpu:a40:1` when the job fits 30 minutes.

---

### Task 1: Add capability-plus-provenance arm semantics

**Files:**
- Modify: `src/agentsec/schemas.py`
- Modify: `src/agentsec/policy.py`
- Modify: `src/agentsec/agents.py`
- Test: `tests/test_policy.py`, `tests/test_orchestrator.py`

**Interfaces:**
- Produces `DefenseArm.CAPABILITY_PROVENANCE_ONLY = "capability_provenance_only"`.
- Capability enforcement and provenance sink checks are enabled for the new arm.
- Safe prompt and blocked-call recovery remain disabled, matching `capability_only`.

- [ ] Write a failing policy test asserting an authorized exact-secret sink call is allowed by `capability_only` but denied by `capability_provenance_only`.
- [ ] Run `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_policy -q` and observe the missing enum/behavior failure.
- [ ] Implement the enum, sink-check arm tuple, and no-recovery semantics.
- [ ] Run the focused policy/orchestrator tests and require zero failures.
- [ ] Run the full 93-test suite and commit the arm semantics.

### Task 2: Freeze and run the 54-cell capability-plus-provenance plan

**Files:**
- Modify: `src/agentsec/runplan.py`
- Create: `scripts/freeze_capability_provenance_plan.py`
- Create: `scripts/run_capability_provenance.slurm`
- Create: `configs/frozen/capability_provenance_plan_v1/manifest.json`
- Create: `configs/frozen/capability_provenance_plan_v1/run_plan.jsonl`
- Test: `tests/test_runplan.py`

**Interfaces:**
- `build_capability_provenance_plan(...)` returns 54 `RunSpec` records.
- The frozen manifest has `plan_kind="capability_provenance_ablation"` and exactly one defense arm.

- [ ] Add a failing run-plan test for 54 cells and the new manifest kind.
- [ ] Run the focused run-plan tests and observe the expected missing-plan failure.
- [ ] Implement the plan builder and standalone freeze script without changing old-plan defaults.
- [ ] Add an A40 debug SLURM runner that checks pilot gates, verifies append-only outputs, launches vLLM, runs 54 cells, and returns invalid status after aggregation.
- [ ] Freeze and verify the new plan; record its SHA-256 in the local experiment log.
- [ ] Submit to `debug`, monitor to completion, and validate all 54 records.

### Task 3: Add deterministic provenance sink pressure test

**Files:**
- Create: `scripts/run_sink_pressure_test.py`
- Create: `tests/test_sink_pressure.py`
- Modify: `docs/EXPERIMENT_PROTOCOL.md`

**Interfaces:**
- CLI `python scripts/run_sink_pressure_test.py --output artifacts/sink-pressure-v1/results.json`.
- JSON contains four cases, four arms per case, policy decision, taint IDs, execution status, and pass/fail assertions.

- [ ] Write failing tests for the expected 2×2 sink matrix and four sink-field cases.
- [ ] Run the focused pressure-test tests and observe the missing runner failure.
- [ ] Implement a fresh local world/audit/tracker/gateway per case and execute identical authorized calls.
- [ ] Run the pressure test and assert `capability_only`/`prompt_capability_only` leak while the two provenance arms deny.
- [ ] Commit the runner, tests, and protocol text.

### Task 4: Freeze hardened Red-Agent corpus and paired plan

**Files:**
- Create: `configs/prompts/red_agent_hardened_system.txt`
- Create: `scripts/freeze_hardened_plan.py`
- Create: `scripts/run_hardened.slurm`
- Create: `configs/frozen/hardened_plan_v1/manifest.json`
- Create: `configs/frozen/hardened_plan_v1/run_plan.jsonl`
- Create: `data/frozen/red_corpus_qwen3_hardened_v1/...`
- Test: `tests/test_redteam.py`, `tests/test_runplan.py`

**Interfaces:**
- Hardened corpus is generated by the existing vLLM-backed offline generator with a distinct system-prompt hash and corpus manifest.
- Hardened plan has only `prompt_capability_only` and `full`, 108 total cells (six scenarios × three conditions × two arms × three seeds).

- [ ] Add failing validation tests for the hardened prompt marker/hash and two-arm 108-cell plan.
- [ ] Run focused tests and observe missing hardened configuration failure.
- [ ] Implement the frozen prompt and plan script; use fixed candidate index 4 for formal attack payloads.
- [ ] Submit offline generation on debug A40, verify the corpus, then freeze the paired plan before victim evaluation.
- [ ] Run the paired hardened plan on debug A40 and preserve all raw artifacts.

### Task 5: Analyze and report the new evidence

**Files:**
- Modify: `src/agentsec/analysis.py`, `scripts/analyze_results.py`
- Create: `artifacts/hardened-analysis-v1/...`
- Modify: `README.md`, `README_ZH.md`, ignored report source and tracked `report/main.pdf`
- Test: `tests/test_analysis.py`

**Interfaces:**
- Analysis labels original, first-ablation, capability-provenance, pressure-test, and hardened families separately.
- Report states whether Prompt+Capability leakage is nonzero on hardened attacks before discussing any Full improvement.

- [ ] Write failing analysis tests for the new arm/family comparison selectors.
- [ ] Run focused analysis tests and observe the missing selectors.
- [ ] Implement family-aware aggregation and registered paired contrasts.
- [ ] Aggregate the new run records, regenerate tables/figures, update both READMEs and the PDF.
- [ ] Run full tests, compile PDF with TinyTeX, inspect artifacts, and commit without pushing.
