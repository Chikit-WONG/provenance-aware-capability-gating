# Task 2 implementation report — strengthened PACT runner

Status: DONE

## Scope

Implemented the deterministic strengthened experiment on the local `ckw`
branch. No model, AgentDojo job, remote push, or historical artifact was
changed. The new artifact is deliberately small and covers the real
`PACTToolGateway`/`ToolExecutor` boundary plus the eight-case policy matrix.

## TDD evidence

1. Added `tests/test_pact_strengthened_runner.py` before the runner.
2. Required RED command:

   ```text
   PYTHONPATH=src python -m unittest tests.test_pact_strengthened_runner -v
   ```

   Failed during import as expected with
   `ModuleNotFoundError: No module named 'scripts.run_pact_strengthened'`.
3. Implemented `scripts/run_pact_strengthened.py` with exact
   `NormalizeEmailAddress` provenance registration, paired fresh-world calls,
   eight strategy rows, LF-canonical writers, SVG, and output hash validation.
4. Focused GREEN command:

   ```text
   PYTHONPATH=src python -m unittest tests.test_pact_strengthened_runner -v
   ```

   `Ran 5 tests ... OK`.
5. Related regression command:

   ```text
   PYTHONPATH=src python -m unittest tests.test_pact_tool_gateway tests.test_pact tests.test_world_tools -v
   ```

   `Ran 15 tests ... OK`.
6. Full suite command:

   ```text
   PYTHONPATH=src python -m unittest discover -s tests -q
   ```

   `Ran 181 tests ... OK (skipped=1)`.
7. Syntax/integrity checks passed:

   ```text
   python -m py_compile scripts/run_pact_strengthened.py tests/test_pact_strengthened_runner.py
   git diff --check -- scripts/run_pact_strengthened.py tests/test_pact_strengthened_runner.py
   bash -n scripts/compile_report.sh
   ```

## Artifact

The formal local command was:

```text
PYTHONPATH=src python scripts/run_pact_strengthened.py \
  --output-dir artifacts/pact-strengthened-v1
```

The destination did not exist before the run and the runner refuses a second
run into the same directory. The artifact contains six end-to-end records
(three cases paired across capability-only and PACT), eight strategy rows,
seven output files, a JSONL decision log, Mermaid architecture, and an SVG
strategy plot. A final audit reported:

```text
outputs= 7 e2e= 6 strategy= 8 sha256=OK LF=OK
```

The key paired result is: external allow-listed Bob is sent by
capability-only (`outbox_count=1`) but denied by PACT before the tool call
(`outbox_count=0`); explicit user Bob and external content sent to user Alice
are allowed by both policies. The matrix additionally covers registered,
unregistered, and explicitly untrusted external `NormalizeEmailAddress`
metadata, plus `control` bindings.

The artifact directory is ignored by the repository's broad `artifacts/*`
rule, so it was force-added with `git add -f` to make the formal result
available in the branch. No existing artifact was removed or replaced.

## Commit

`feat: add strengthened PACT experiment artifacts`

