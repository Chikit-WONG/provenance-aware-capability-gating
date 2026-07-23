# Task 3 implementation report

Status: implementation complete; official freeze execution is blocked by the
HPC Conda/network layer.

## Implemented

- Added `scripts/freeze_agentdojo_external.py` with lazy AgentDojo imports,
  official `get_suite`/`AgentPipeline([])`/`load_attack` screening, both pinned
  attacks, persisted exclusion reasons, deterministic hash-order selection,
  strict 18-pair development/formal plans, exclusive writes, environment
  evidence, and `--verify` coverage/hash checks.
- Added a deterministic recursive checkpoint fingerprint over relative file
  paths, sizes, and bytes (mtime independent).
- Extended the frozen manifest with optional screening, selected-pair, and
  environment digests while preserving old fixtures.
- Added focused tests for exclusive freeze output, artifact hashes,
  checkpoint fingerprint stability, and model-name compatibility registration.

## Verification

Focused command:

```text
PYTHONPATH=src conda run -n test python -m unittest discover -s tests -p 'test_agentdojo_external.py' -v
Ran 13 tests in 5.471s
OK (skipped=1)
```

The one skip is the compatibility test because the pinned AgentDojo package is
intentionally absent from the controller `test` environment.

Full command:

```text
PYTHONPATH=src conda run -n test python -m unittest discover -s tests -v
Ran 122 tests in 9.104s
OK (skipped=1)
```

## Blocked execution

The required isolated environment was not present. Running
`bash scripts/bootstrap_agentdojo_external.sh` attempted to create it, but
Conda failed while fetching the configured mirror metadata with repeated
`SSLEOFError`/`CondaSSLError` failures for
`mirrors.tuna.tsinghua.edu.cn`. Therefore no official AgentDojo screening was
run and no checked-in frozen manifest or selected-pair artifacts were
fabricated. Once the pinned environment is available, run the exact Task 3
freeze and verification commands from the brief; the generated directory is
deliberately excluded from this commit until that pre-inference screen has
actually completed.
