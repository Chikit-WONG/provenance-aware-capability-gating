# Full AgentDojo Suite + Canonical Attacks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the native AgentDojo validation to all four v1.2.2 suites with the two canonical attacks, two existing defenses, clean utility controls, exact frozen coverage, and publication-ready aggregate analysis.

**Architecture:** Keep the project-owned contracts independent of AgentDojo, but add validated suite identity and generic canonical attack fields. Freeze one immutable sub-plan per suite beneath a top-level matrix manifest, run rows through the existing one-row runner and bounded Slurm arrays, then merge selected records only through a top-level attempt-selection manifest and suite-aware analyzer.

**Tech Stack:** Python 3.11, Pydantic v2, AgentDojo v0.1.35 at commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`, Qwen3-VL-8B-Instruct, vLLM, Bash, Slurm debug/A40, `unittest`.

## Global Constraints

- Use only AgentDojo suites `workspace`, `travel`, `banking`, and `slack` from benchmark `v1.2.2`.
- Use only official attacks `important_instructions` and `tool_knowledge`; do not add `manual`, DoS attacks, or new defenses.
- Use defenses `none` and `repeat_user_prompt`; clean rows have `attack="none"` and no injection task.
- Preserve the local checkpoint `/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct`, served name `qwen3-vl-8b`, temperature `0.0`, JSON tool output, and default 16K context.
- Freeze all pair applicability and plan bytes before inference; rerunning a destination must fail rather than overwrite it.
- Development and formal cells are disjoint; formal analysis must fail closed on missing, duplicate, invalid, or hash-drifted rows.
- Keep official traces ignored; commit compact records, frozen plans/manifests, derived tables/figures, and documentation only.
- Run tests with `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest discover -s tests -v`.
- Run benchmark commands with proxy variables removed and the existing `agentdojo-external` environment; do not download a model.

---

### Task 1: Generalize the AgentDojo contracts and matrix builders

**Files:**
- Modify: `src/agentsec/agentdojo_external.py`
- Test: `tests/test_agentdojo_external.py`
- Test: `tests/test_agentdojo_external_analysis.py`

**Interfaces:**
- Produce `AGENTDOJO_SUITES = ("workspace", "travel", "banking", "slack")`, `CANONICAL_ATTACKS = ("important_instructions", "tool_knowledge")`, and `DEFENSES = ("none", "repeat_user_prompt")` as exported tuples.
- Change `canonical_pair(user_task_id, injection_task_id, suite_name="workspace") -> AgentDojoPair` so the canonical key is `{suite_name}:v1.2.2:{user}:{injection}` and the pair validates its suite.
- Add `suite: str = "workspace"` to `AgentDojoRunSpec` and `AgentDojoResultRecord`, validate it against `AGENTDOJO_SUITES`, and include it in derived run IDs. Keep old JSON fixtures valid through the default.
- Replace the narrow attack `Literal` fields with validators that accept exactly `none` or a member of `CANONICAL_ATTACKS`; keep defense validation exact.
- Add `build_matrix_plan(pairs, model_config_hash, *, phase, suite_name, clean_user_task_ids) -> list[AgentDojoRunSpec]` that emits every pair × attack × defense followed by each requested clean user × defense. It accepts arbitrary runnable pair counts and rejects duplicate pairs, wrong suite, and cross-phase overlap inputs.
- Keep `build_development_plan` and `build_formal_plan` as backward-compatible Workspace wrappers with their current two-pair/sixteen-pair contract so the existing frozen slice remains verifiable.
- Extend `validate_agentdojo_plan` to compare suite and generic attack fields while preserving the legacy wrapper behavior.

- [ ] **Step 1: Add failing contract tests.** Add tests that construct Travel and Slack pairs, assert distinct canonical keys/run IDs, build a two-pair generic matrix with 16 attacked and four clean cells, reject an unsupported suite/attack, and verify existing Workspace wrapper counts remain unchanged.

```python
def test_generic_matrix_is_suite_aware(self):
    pairs = [canonical_pair("u1", "i1", "travel"), canonical_pair("u2", "i2", "travel")]
    rows = build_matrix_plan(
        pairs, _MODEL_HASH, phase="formal", suite_name="travel", clean_user_task_ids=("u1",)
    )
    self.assertEqual(len([row for row in rows if row.attack != "none"]), 16)
    self.assertEqual(len([row for row in rows if row.attack == "none"]), 2)
    self.assertEqual({row.suite for row in rows}, {"travel"})
```

- [ ] **Step 2: Run the focused tests to verify the new assertions fail.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_agentdojo_external -v`

Expected: FAIL because the current contracts only encode Workspace and the two fixed pair partition sizes.

- [ ] **Step 3: Implement the minimal generic contracts and builder.** Preserve old defaults and old error messages where existing tests depend on them; use one suite parser for canonical keys and one validator for allowed suites/attacks.

- [ ] **Step 4: Run focused and analysis contract tests.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_agentdojo_external tests.test_agentdojo_external_analysis -v`

Expected: PASS, including all existing Workspace tests and the new suite-aware cases.

- [ ] **Step 5: Commit.**

```bash
git add src/agentsec/agentdojo_external.py tests/test_agentdojo_external.py tests/test_agentdojo_external_analysis.py
git commit -m "feat: generalize AgentDojo suite contracts"
```

### Task 2: Freeze the four-suite canonical matrix

**Files:**
- Modify: `scripts/freeze_agentdojo_external.py`
- Create: `configs/external/agentdojo_external_full_v1.json`
- Create: `scripts/freeze_agentdojo_external_full.py`
- Test: `tests/test_agentdojo_external.py`
- Test: `tests/test_agentdojo_external_config.py`

**Interfaces:**
- Produce `freeze_full(config_path, output_root, enumerator=enumerate_official_pairs) -> dict[str, Any]` and `verify_full(output_root, config_path) -> dict[str, Any]`.
- Use the existing official attack loader for each suite; pass `suite_name` to `canonical_pair` and record suite in every screening row.
- Write `configs/frozen/agentdojo_external_full_v1/plan_manifest.json` and four subdirectories, each containing `manifest.json`, `screening.jsonl`, `selected_pairs.jsonl`, `environment.txt`, `development_plan.jsonl`, and `formal_plan.jsonl`.
- Select two runnable attacked pairs and two clean user IDs per suite for development using sorted canonical SHA-256 order; formal contains every remaining runnable pair and clean user ID. Record exact counts and SHA-256 hashes in both the per-suite and top-level manifests.
- Validate config keys `suites`, `attacks`, `defenses`, model identity, benchmark identity, temperature, and tool-output format; reject the old single-suite config when invoking the full freezer.

- [ ] **Step 1: Add failing freeze tests.** Mock the enumerator for all four suites and assert deterministic output, 2 development attacked pairs per suite, disjoint formal rows, exact clean/attacked counts, top-level sub-manifest hashes, and exclusive second-freeze failure.

```python
summary = freeze_full(config_path, root / "frozen", enumerator=fake_enumerator)
self.assertEqual(summary["suite_count"], 4)
self.assertEqual(summary["formal_total_count"], summary["formal_attacked_count"] + summary["formal_clean_count"])
with self.assertRaises(FileExistsError):
    freeze_full(config_path, root / "frozen", enumerator=fake_enumerator)
```

- [ ] **Step 2: Run the freeze tests to verify they fail.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_agentdojo_external.AgentDojoExternalTests.test_full_freeze_is_deterministic -v`

Expected: FAIL because the current freezer accepts only one Workspace destination.

- [ ] **Step 3: Implement the full freezer and pinned JSON config.** Keep the existing `freeze_slice` and old config untouched for regression; place new code in the dedicated full-freezer module when this keeps legacy verification simpler.

- [ ] **Step 4: Verify the full freezer without model inference.**

Run: `env -u LD_LIBRARY_PATH -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY /hpc2hdd/home/ckwong627/miniconda3/envs/agentdojo-external/bin/python scripts/freeze_agentdojo_external_full.py --config configs/external/agentdojo_external_full_v1.json --output configs/frozen/agentdojo_external_full_v1`

Expected: one summary JSON line reporting all four suites, the frozen pair inventory, and development/formal counts; no vLLM process or network socket is opened.

- [ ] **Step 5: Verify and commit the frozen plan.**

```bash
env -u LD_LIBRARY_PATH -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY /hpc2hdd/home/ckwong627/miniconda3/envs/agentdojo-external/bin/python scripts/freeze_agentdojo_external_full.py --verify configs/frozen/agentdojo_external_full_v1 --config configs/external/agentdojo_external_full_v1.json
git add scripts/freeze_agentdojo_external.py scripts/freeze_agentdojo_external_full.py configs/external/agentdojo_external_full_v1.json configs/frozen/agentdojo_external_full_v1 tests/test_agentdojo_external.py tests/test_agentdojo_external_config.py
git commit -m "results: freeze full AgentDojo canonical matrix"
```

### Task 3: Make execution and Slurm submission suite-aware

**Files:**
- Modify: `scripts/run_agentdojo_external.py`
- Modify: `scripts/run_agentdojo_external.slurm`
- Modify: `scripts/submit_agentdojo_external_wave.sh`
- Create: `scripts/submit_agentdojo_external_full_wave.sh`
- Test: `tests/test_agentdojo_external_config.py`
- Test: `tests/test_agentdojo_external.py`

**Interfaces:**
- `_benchmark_functions(pipeline, attack_name, suite_name="workspace")` loads `get_suite("v1.2.2", suite_name)` and the attack against that suite.
- `run_slice` and `run_row` consume the suite embedded in `AgentDojoRunSpec`; no CLI caller supplies a second conflicting suite.
- The launcher resolves `AGENTDOJO_FROZEN_ROOT/<suite>/development_plan.jsonl` or `formal_plan.jsonl` when `--suite` is supplied, and writes to `artifacts/agentdojo-external-full-v1` by default.
- The wave submitter accepts `PHASE PLAN [rows-per-shard] [shard-start] [wave-shards]`, preserves the existing array bounds, and derives logs/artifacts from the full root without hard-coded Workspace paths.
- `scripts/submit_agentdojo_external_full_wave.sh` iterates the four suite plan directories, submits one bounded array per suite, and refuses to submit when a suite plan is missing or empty.

- [ ] **Step 1: Add failing execution tests.** Use a stub suite loader and assert `_benchmark_functions(..., "travel")` requests Travel, `run_slice` passes a Travel row unchanged, and full launcher text contains the full artifact root and suite argument.

- [ ] **Step 2: Run focused execution/config tests to verify failure.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_agentdojo_external tests.test_agentdojo_external_config -v`

Expected: FAIL on the new Travel loader and full-root assertions.

- [ ] **Step 3: Implement suite-aware loading, artifact-root selection, launcher arguments, and the four-suite wave wrapper.** Preserve the existing proxy unsets, readiness loop, deterministic ports, 30-minute debug partition, and offline environment variables.

- [ ] **Step 4: Run focused tests and a no-model runner stub.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_agentdojo_external tests.test_agentdojo_external_config -v`

Expected: PASS; the stub must produce one valid compact record with `suite="travel"` and no external endpoint call.

- [ ] **Step 5: Commit.**

```bash
git add scripts/run_agentdojo_external.py scripts/run_agentdojo_external.slurm scripts/submit_agentdojo_external_wave.sh scripts/submit_agentdojo_external_full_wave.sh tests/test_agentdojo_external.py tests/test_agentdojo_external_config.py
git commit -m "feat: run AgentDojo rows across all suites"
```

### Task 4: Select, validate, and analyze the aggregate formal benchmark

**Files:**
- Modify: `scripts/select_external_attempts.py`
- Modify: `scripts/analyze_agentdojo_external.py`
- Modify: `src/agentsec/agentdojo_external_analysis.py`
- Create: `scripts/select_agentdojo_external_full.py`
- Test: `tests/test_agentdojo_external_analysis.py`
- Test: `tests/test_agentdojo_external_config.py`

**Interfaces:**
- Produce `select_full_attempts(plan_root, artifact_root, output_path) -> dict[str, Any]`; it combines four per-suite plans, computes a deterministic aggregate plan hash from the suite plan hashes, and writes one top-level selection manifest with one row per formal run.
- `validate_formal_records` checks suite identity as part of `record.run_spec == plan_row` and rejects cross-suite duplicates or records from the old Workspace root.
- `summarize_records` groups attacked rows by `(suite, attack, defense)` and clean rows by `(suite, defense)`, then emits `overall_attack_summary`, `suite_attack_summary`, `overall_clean_utility`, and `suite_clean_utility` while retaining the old keys for a single-suite input.
- `write_analysis_bundle` adds suite columns to CSV/LaTeX and generates a four-panel suite figure without changing the metric semantics: official targeted ASR is not inverted and clean utility has its own denominator.
- The aggregate CLI accepts `--plan-root configs/frozen/agentdojo_external_full_v1`, `--records artifacts/agentdojo-external-full-v1`, `--attempt-selection .../attempt_selection.json`, and `--output-dir .../agentdojo-external-full-analysis-v1`.

- [ ] **Step 1: Add failing aggregation tests.** Build two formal rows for each of two suites, select attempts from two artifact roots, assert a top-level manifest has all run IDs, and assert summaries contain distinct suite keys with separate clean denominators.

```python
report = summarize_records(records)
self.assertIn("suite_attack_summary", report)
self.assertEqual({row["suite"] for row in report["suite_attack_summary"]}, {"workspace", "travel"})
self.assertEqual({row["suite"] for row in report["suite_clean_utility"]}, {"workspace", "travel"})
```

- [ ] **Step 2: Run analysis tests to verify they fail.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest tests.test_agentdojo_external_analysis -v`

Expected: FAIL because summaries currently discard suite identity and selection handles one plan only.

- [ ] **Step 3: Implement aggregate selection and suite-aware analysis.** Use exclusive writes, hash every selected record, and preserve the existing single-suite CLI path for old artifacts.

- [ ] **Step 4: Run the full test suite.**

Run: `PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest discover -s tests -v`

Expected: all existing and new tests pass, with only the existing AgentDojo-unavailable skip.

- [ ] **Step 5: Commit.**

```bash
git add scripts/select_external_attempts.py scripts/select_agentdojo_external_full.py scripts/analyze_agentdojo_external.py src/agentsec/agentdojo_external_analysis.py tests/test_agentdojo_external_analysis.py tests/test_agentdojo_external_config.py
git commit -m "feat: aggregate full AgentDojo validation"
```

### Task 5: Run the benchmark and publish reproducible evidence

**Files:**
- Modify: `docs/EXTERNAL_VALIDATION.md`
- Modify: `README.md`
- Modify: `README_ZH.md`
- Create: `artifacts/agentdojo-external-full-analysis-v1/results_summary.json`
- Create: `artifacts/agentdojo-external-full-analysis-v1/attack_summary.csv`
- Create: `artifacts/agentdojo-external-full-analysis-v1/clean_utility.csv`
- Create: `artifacts/agentdojo-external-full-analysis-v1/publication_table.tex`
- Create: `artifacts/agentdojo-external-full-analysis-v1/agentdojo_outcomes.png`

**Interfaces:**
- Use the frozen plan only; do not alter it after the first development submission.
- Submit development once, inspect all compact records, then submit formal shards in waves of at most eight rows with at most two concurrent debug jobs.
- After all shards finish, run full attempt selection and fail if `selected_count != formal_total_count` or any selected record is invalid.
- Publish only aggregate metrics generated by `write_analysis_bundle`; include suite-level counts and the exact plan/selection/analysis hashes in the documentation.

- [ ] **Step 1: Submit development rows with the local model.**

Run: `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY bash scripts/submit_agentdojo_external_full_wave.sh development configs/frozen/agentdojo_external_full_v1`

Expected: one successful Slurm job per suite or one combined development array, with compact records for every development row and no missing vLLM readiness logs.

- [ ] **Step 2: Submit formal waves and monitor them.**

Run: `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY bash scripts/submit_agentdojo_external_full_wave.sh formal configs/frozen/agentdojo_external_full_v1 8 0 10` and repeat with the next shard start until the frozen formal count is covered; inspect `sacct` for every array task before advancing a wave.

Expected: each shard exits zero or is explicitly resubmitted with `attempt-0002`; no shard changes the plan or denominator.

- [ ] **Step 3: Select attempts and analyze.**

Run:

```bash
env -u LD_LIBRARY_PATH -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY /hpc2hdd/home/ckwong627/miniconda3/envs/agentdojo-external/bin/python scripts/select_agentdojo_external_full.py --plan-root configs/frozen/agentdojo_external_full_v1 --artifact-root artifacts/agentdojo-external-full-v1 --output configs/frozen/agentdojo_external_full_v1/attempt_selection.json
env -u LD_LIBRARY_PATH -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY /hpc2hdd/home/ckwong627/miniconda3/envs/agentdojo-external/bin/python scripts/analyze_agentdojo_external.py --plan-root configs/frozen/agentdojo_external_full_v1 --records artifacts/agentdojo-external-full-v1 --attempt-selection configs/frozen/agentdojo_external_full_v1/attempt_selection.json --output-dir artifacts/agentdojo-external-full-analysis-v1
```

Expected: every formal row selected exactly once; JSON/CSV/LaTeX/PNG outputs and a hash manifest are created exclusively.

- [ ] **Step 4: Update documentation with observed results.** Add a compact English/Chinese table for overall and four-suite ASR/utility, state that AgentDojo security is an external metric, and link the committed artifacts without copying raw traces.

- [ ] **Step 5: Verify, commit, and report.**

Run: `git diff --check && PYTHONPATH=src /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python -m unittest discover -s tests -v && git status --short --branch`

Expected: no whitespace errors, all tests pass, and the local `ckw` branch is clean after commit.

```bash
git add docs/EXTERNAL_VALIDATION.md README.md README_ZH.md configs/frozen/agentdojo_external_full_v1/ artifacts/agentdojo-external-full-analysis-v1/
git commit -m "results: add full AgentDojo canonical validation"
```
