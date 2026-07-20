# Task 1 Report: Defense-arm semantics

## Status

Implemented `DefenseArm.PROMPT_CAPABILITY_ONLY` with:

- the stable serialized value `prompt_capability_only`;
- capability-manifest enforcement;
- no provenance/taint sink blocking;
- the same untrusted-data system prompt as `full`;
- the same blocked-call recovery continuation as `full`.

The existing four arms retain their prior policy, prompt, and recovery behavior.

## TDD evidence

### Prescribed command availability

Command:

```bash
conda run -n test pytest tests/test_policy.py tests/test_orchestrator.py -q
```

Result before production edits: exit 127 because the `test` environment does
not contain a `pytest` executable (`pytest: command not found`). The repository
declares and uses `unittest` in `scripts/run_tests.sh`, so the focused TDD cycle
used the same Python environment with the repository-supported runner.

### RED

Command, after adding tests and before production edits:

```bash
env PYTHONPATH="$PWD/src:$PWD/tests" \
  conda run -n test python -m unittest test_policy test_orchestrator -v
```

Result: exit 1; 17 tests ran, with five expected errors. Every new test failed
at the intended missing interface:

```text
AttributeError: PROMPT_CAPABILITY_ONLY
FAILED (errors=5)
```

The pre-existing 12 focused tests remained green.

### GREEN

The same focused `unittest` command after the minimal production changes:

```text
Ran 17 tests in 0.115s
OK
```

This includes focused coverage for enum serialization, out-of-manifest
recipient denial, registered-secret allowance without taint blocking, protected
Reader and Action system prompts, and recovery-continuation parity with
`DefenseArm.FULL`.

## Full-suite evidence

Command:

```bash
bash scripts/run_tests.sh
```

Result: 83 tests ran; 80 passed and three errored. The only failures are the
known next-task run-plan boundary:

```text
ValueError: expected 216 formal runs, found 270
FAILED (errors=3)
```

They occur because `src/agentsec/runplan.py` currently constructs the old
formal design with `tuple(DefenseArm)`. Task 2 owns replacing that implicit
enumeration with explicit formal and ablation arm sets. No Task 2 files were
changed in this commit.

## Files changed

- `src/agentsec/schemas.py`
- `src/agentsec/agents.py`
- `src/agentsec/policy.py`
- `tests/test_policy.py`
- `tests/test_orchestrator.py`
- `.superpowers/sdd/task-1-report.md`

## Concerns

- The exact requested pytest command cannot run until pytest is installed in
  the `test` conda environment; the repository-supported unittest equivalent
  is green.
- The full suite will remain three tests short of green until Task 2 makes the
  legacy 216-run formal arm set explicit.
