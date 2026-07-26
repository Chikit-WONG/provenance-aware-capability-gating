# PACT strengthened evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reproducible end-to-end MockWorld PACT evaluation and an eight-case role/transformation matrix without expanding the benchmark scope.

**Architecture:** Keep the existing provenance/capability policy core, expose stable decision methods, and add a thin tool-boundary adapter that invokes the repository's `ToolExecutor` only after the selected policy allows.  A new runner executes fresh-world paired cases, writes canonical LF artifacts, and produces a compact matrix plot plus manifest.

**Tech Stack:** Python 3, Pydantic models, existing `ToolExecutor`/`MockWorld`, `unittest`, CSV/JSON, matplotlib SVG output.

## Global Constraints

- Preserve `artifacts/pact-minimum-v2` and historical AgentDojo artifacts.
- New outputs use `artifacts/pact-strengthened-v1` and refuse overwrite.
- `NormalizeEmailAddress` is the only registered transformation in the new artifact.
- Persisted text and CSV output must use LF line endings.
- Capability-only executes based only on the value allow-list; PACT executes only when both capability and provenance checks allow.
- End-to-end PACT denial must not call `ToolExecutor` and must leave `MockWorld.outbox` unchanged.
- No new AgentDojo/model/seed/SLURM work; no remote push.

---

### Task 1: Expose policy decisions and add the real tool-boundary adapter

**Files:**
- Modify: `src/agentsec/pact.py`
- Create: `src/agentsec/pact_tool_gateway.py`
- Test: `tests/test_pact_tool_gateway.py`

**Interfaces:**
- Add public `PACTGateway.capability_decision(call) -> tuple[bool, str]` and `PACTGateway.pact_decision(call) -> tuple[bool, bool, str]`; existing `execute()` must retain its behavior.
- Add `PACTToolResult` with policy, both decisions, tool execution status/event, outbox count, reason, provenance digests, and decision hash.
- Add `PACTToolGateway.execute_send_email(call, case_id, policy) -> PACTToolResult`, where `policy` is `"capability_only"` or `"pact"`.

- [ ] **Step 1: Write failing tests** for capability-only external Bob sending through `ToolExecutor`, PACT external Bob being blocked before `ToolExecutor`, user Bob being sent by PACT, and external content being sent by PACT.
- [ ] **Step 2: Run** `PYTHONPATH=src python -m unittest tests.test_pact_tool_gateway -v` and observe failures because the adapter/API is absent.
- [ ] **Step 3: Implement** public decision wrappers and the adapter.  Map `recipient` to `send_email.to`, `content` to `send_email.body`, and optional `subject` to `send_email.subject`; use fresh `WorldState()`/`AuditLog()` supplied by the caller.
- [ ] **Step 4: Run** the focused test and then `PYTHONPATH=src python -m unittest tests.test_pact tests.test_world_tools tests.test_pact_tool_gateway -v`.
- [ ] **Step 5: Commit** with message `feat: add PACT real tool boundary adapter`.

### Task 2: Add normalization, eight-case runner, LF artifacts, and plot

**Files:**
- Modify: `scripts/run_pact_strengthened.py` (create if absent)
- Modify: `tests/test_pact_tool_gateway.py`
- Create: `tests/test_pact_strengthened_runner.py`
- Create: `scripts/plot_pact_strategy.py` (if the plot is not kept in the runner)

**Interfaces:**
- `normalize_email_address(value: str) -> str` returns `value.strip().lower()`.
- `run(output_dir: Path) -> dict[str, Any]` writes the strengthened artifact and refuses existing directories.
- Artifact contains `e2e_results.json`, `e2e_results.csv`, `strategy_results.json`, `strategy_results.csv`, `decision_log.jsonl`, `strategy_matrix.svg`, `architecture.mmd`, and `manifest.json`.

- [ ] **Step 1: Write failing tests** for normalization, registered versus unregistered transformation decisions, the eight expected matrix rows, LF-only outputs, and refusal to overwrite.
- [ ] **Step 2: Run** `PYTHONPATH=src python -m unittest tests.test_pact_strengthened_runner -v` and observe expected failures.
- [ ] **Step 3: Implement** the runner using fresh gateways/worlds per paired policy run, `NormalizeEmailAddress`, explicit untrusted-transform metadata for the external registered-transform row, and a `csv.DictWriter(..., lineterminator="\\n")`.
- [ ] **Step 4: Generate** the SVG with the existing matplotlib environment, write all text using explicit LF bytes, compute hashes from final bytes, and validate the manifest before returning.
- [ ] **Step 5: Run** focused runner tests and the script into a temporary directory; verify the printed counts and hashes.
- [ ] **Step 6: Commit** with message `feat: add strengthened PACT experiment artifacts`.

### Task 3: Update documentation and report wording

**Files:**
- Modify: `docs/PACT_MINIMUM.md`
- Modify: `README.md`
- Modify: `README_ZH.md`
- Modify: `report/main.tex`
- Modify: `report/provenance-aware-capability-gating-report/main.tex` if the nested Overleaf source is present

- [ ] **Step 1: Add** a concise “strengthened PACT evidence” paragraph and tables linking the new artifact, explicitly separating real MockWorld side effects from the decision-only matrix.
- [ ] **Step 2: Replace** the Base64 recipient wording with `NormalizeEmailAddress`; describe exact-match verification over an append-only registry.
- [ ] **Step 3: State** that AgentDojo remains external attack-realism evidence and is not merged into PACT metrics.
- [ ] **Step 4: Compile** the report with TinyTeX and check for LaTeX errors/overfull boxes.
- [ ] **Step 5: Commit** with message `docs: report strengthened PACT evidence`.

### Task 4: Whole-branch verification and review

**Files:**
- No new production files; inspect all Task 1–3 changes.

- [ ] **Step 1: Run** the full unit-test suite with `scripts/run_tests.sh`.
- [ ] **Step 2: Run** `bash -n scripts/run_pact_strengthened.py scripts/plot_pact_strategy.py scripts/compile_report.sh` where applicable and `git diff --check`.
- [ ] **Step 3: Re-run** the strengthened artifact in a fresh temporary directory and verify all manifest hashes, case coverage, LF endings, and outbox assertions.
- [ ] **Step 4: Confirm** `squeue` shows no new AgentDojo job submitted by this work and `git status` shows no remote push.
- [ ] **Step 5: Record** final artifact paths, commit IDs, test counts, and known limits in the SDD ledger.
