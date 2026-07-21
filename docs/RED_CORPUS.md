# Offline Red-Agent corpus

The Red Agent is a data-generation stage, not a runtime agent. Formal victim
runs load a verified frozen bundle and therefore have no code path or model
client that can ask the Red Agent for another payload.

## Registered selection rule

Every T1--T6 scenario is generated once with seeds `431301` through `431305`.
Candidate indices 1--3 are development payloads, index 4 is selected by rule for
the formal condition, and index 5 remains an unused reserve. The reserve guard
accepts index 5 only for a `syntax_or_format_defect` recorded before any victim
run. Victim success, attack rate, or model behavior can never authorize a
replacement.

Each call must return exactly one JSON object with `payload`, `strategy`, and
`target`. The generator retains the full message list, raw response, normalized
object, fixed seed, model ID, and SHA-256 values. It makes one call per
scenario/seed and performs no outcome-based retry or search.

## Generate and verify

The stub backend is a deterministic infrastructure fixture. Its manifest is
marked `formal_eligible=false`:

```bash
python scripts/generate_red_corpus.py \
  --backend stub \
  --output /tmp/red-corpus-stub
python scripts/validate_red_corpus.py --allow-stub /tmp/red-corpus-stub
```

With the local vLLM endpoint already running, generate the formal-eligible
bundle exactly once at a new destination:

```bash
python scripts/generate_red_corpus.py \
  --backend vllm \
  --base-url http://127.0.0.1:8000/v1 \
  --model qwen3-vl-8b \
  --output data/frozen/red_corpus_qwen3_v1
python scripts/validate_red_corpus.py data/frozen/red_corpus_qwen3_v1
```

The independent hardened follow-up uses the separate system prompt and an
explicit context-only validation profile. It is already frozen in this
repository; to regenerate it on a new destination, pass:

```bash
python scripts/generate_red_corpus.py \
  --backend vllm --model qwen3-vl-8b \
  --system-prompt configs/prompts/red_agent_hardened_system.txt \
  --validation-profile hardened \
  --output data/frozen/red_corpus_qwen3_hardened_v1
```

The hardened profile allows an address only when it is already present in the
scenario's synthetic context. It does not broaden the strict profile used by
the original formal corpus.

Generation is atomic and refuses an existing destination. Every content file is
made read-only, `manifest.json` hashes the exact tracked file set, and
`manifest.sha256` seals the manifest. Verification rejects modified, missing,
symlinked, or unexpected files and re-runs semantic checks on every stored raw
response, candidate role, condition, and scenario overlay.

## Runner interface

The bundle contains these stable paths:

```text
manifest.json
manifest.sha256
candidates/T1/candidate-1.json ... candidate-5.json
payloads/T1/clean.txt
payloads/T1/candidate-1-attack.txt ... candidate-5-attack.txt
payloads/T1/candidate-1-placebo.txt ... candidate-5-placebo.txt
scenarios/T1.json ... T6.json
```

The frozen scenario files use confined `file:` references. Candidate 4's attack
and matched placebo are the only formal Attack/Placebo references. A formal
runner should use:

```python
from agentsec.redteam import (
    load_candidate_scenarios,
    load_frozen_scenarios,
    materialize_frozen_condition,
    verify_frozen_corpus,
)

manifest = verify_frozen_corpus("data/frozen/red_corpus_qwen3_v1")
scenarios = load_frozen_scenarios("data/frozen/red_corpus_qwen3_v1")
world = materialize_frozen_condition(
    "data/frozen/red_corpus_qwen3_v1", "T1", "attack"
)

# Pilot only: in-memory refs select development candidate 1, 2, or 3.
pilot_scenarios = load_candidate_scenarios(
    "data/frozen/red_corpus_qwen3_v1", candidate_index=2
)
```

The loader requires `formal_eligible=true` by default. Tests and dry runs may
explicitly pass `require_formal_eligible=False` for stub bundles.
`load_candidate_scenarios` rejects indices 4 and 5, never writes the bundle, and
does not alter the fixed candidate-4 mapping returned by `load_frozen_scenarios`.

The placebo constructor uses the same carrier location and registered tone
label, has exactly the attack's UTF-8 byte length, and contains no imperative,
synthetic attack recipient/resource identifier, or registered protected value.
The freeze validator also proves that the three condition worlds are identical
outside the single carrier segment and records a hash for each complete world.
