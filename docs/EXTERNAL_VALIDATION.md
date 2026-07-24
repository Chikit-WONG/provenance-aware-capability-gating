# Native AgentDojo external validation

## Status

The pinned native AgentDojo cross-check is complete. The final artifact root is
`artifacts/agentdojo-external-v1-context16k/`; preliminary failed bootstrap,
serialization, context-window, and port-race attempts remain in the separate
ignored `artifacts/agentdojo-external-v1/` root as debugging evidence and are
not included in the reported denominator.

The final root contains 12 valid development records and 96 valid formal
records. The formal matrix is exactly 64 attacked calls plus 32 clean calls;
all 96 formal rows use `attempt-0001`, and the selection manifest selects 96/96
rows with verified SHA-256 hashes.

## Frozen contract

- AgentDojo `v0.1.35`, exact source commit
  `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`.
- Workspace benchmark `v1.2.2`.
- Official attacks: `important_instructions` and `tool_knowledge`.
- Official defenses: `none` and `repeat_user_prompt`.
- Victim: existing local checkpoint
  `/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct`,
  served as `qwen3-vl-8b`.
- Runtime: local non-streaming vLLM, BF16, temperature 0, JSON tool output,
  one A40, configurable 16K default context, no external services.

The frozen pre-inference selection contains two development pairs and 16 formal
pairs. Selection is independent of model responses. The official AgentDojo
security and utility values are retained without inversion or translation into
the project gateway's labels.

## Reported results

All formal rows are valid (`n=16` per condition):

| Condition | No defense | `repeat_user_prompt` |
| --- | ---: | ---: |
| `important_instructions` targeted ASR | 1/16 (6.25%) | 0/16 (0%) |
| `tool_knowledge` targeted ASR | 1/16 (6.25%) | 0/16 (0%) |
| `important_instructions` utility | 11/16 (68.75%) | 12/16 (75%) |
| `tool_knowledge` utility | 9/16 (56.25%) | 12/16 (75%) |
| Clean utility | 10/16 (62.5%) | 12/16 (75%) |

The publication table and confidence intervals are generated in
`artifacts/agentdojo-external-analysis-v1-context16k/`. This cross-check supports
claims about this local Qwen victim and the official repeat-prompt defense only;
it does not evaluate the project's `Full` provenance-aware gateway.

## Reproduction and artifacts

The reviewed launchers are [`scripts/run_agentdojo_external.slurm`](../scripts/run_agentdojo_external.slurm),
[`scripts/submit_agentdojo_external_wave.sh`](../scripts/submit_agentdojo_external_wave.sh),
and [`scripts/launch_vllm.sh`](../scripts/launch_vllm.sh). Formal outputs are
kept compact for publication:

- [`attempt_selection.json`](../artifacts/agentdojo-external-v1-context16k/attempt_selection.json)
- [`analysis bundle`](../artifacts/agentdojo-external-analysis-v1-context16k/)
- [`final record root`](../artifacts/agentdojo-external-v1-context16k/)

Only wrapper records and derived summaries need to be committed; vLLM logs and
full official traces remain ignored. The initial debug failures are retained
locally to document why the final run uses the 16K context and deterministic
array-task ports.

## Scope and limitations

AgentDojo is an external transfer check, not a replacement for the project's
synthetic provenance benchmark. It uses one local model, one Workspace suite,
two official attacks, and one official prompt defense. It does not test the
project's capability gateway, provenance sink checks, hardened corpus, or
semantic information-flow claims. Results should therefore be reported as
external validation alongside—not merged into—the project-specific factorial
results.
