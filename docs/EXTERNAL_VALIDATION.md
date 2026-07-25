# Native AgentDojo external validation

## Status

The complete pinned native AgentDojo benchmark is finished. The formal artifact
root is `artifacts/agentdojo-external-full-v1/`; all 3,942 formal rows have one
selected `attempt-0001` record and verified SHA-256. There are 3,935 valid rows
and 7 invalid Workspace rows, all retained in the ITT denominator. The 48
development records are kept separately and are not included in the formal
summary.

## Frozen contract

- AgentDojo `v0.1.35`, exact source commit
  `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`.
- Benchmark version `v1.2.2`; suites: Workspace, Travel, Banking, Slack.
- Official attacks: `important_instructions` and `tool_knowledge`.
- Official defenses: `none` and `repeat_user_prompt`.
- Victim: local checkpoint
  `/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct`,
  served as `qwen3-vl-8b`.
- Runtime: local non-streaming vLLM, BF16, one A40, 16K context, offline
  checkpoint, and no external services.
- Formal plan sizes: Workspace 2,308; Travel 588; Banking 596; Slack 450.

The selection manifest is generated only after all formal rows exist. It binds the
aggregate plan hash `d590bbb73203520506d039b2364153dca4e787a6eba18d0a52e553dba2c579f2`
and selects 3,942/3,942 rows.

## Reported results

Valid-only values are shown first; ITT values are in parentheses. Invalid rows are
not silently discarded.

| Attack / defense | Targeted ASR | Attack utility | Clean utility |
| --- | ---: | ---: | ---: |
| `important_instructions` / `none` | 95/940 (95/941) | 637/940 | 64/89 |
| `important_instructions` / `repeat_user_prompt` | 81/940 (81/941) | 610/940 | 65/89 |
| `tool_knowledge` / `none` | 152/937 (152/941) | 584/937 | 64/89 |
| `tool_knowledge` / `repeat_user_prompt` | 97/940 (97/941) | 620/940 | 65/89 |

This external benchmark reports targeted action success and utility. It has no
synthetic-secret outcome, so it is not merged with the project-specific T1--T6
factorial or PACT transformation results.

## Reproduction and artifacts

The launchers are [`scripts/run_agentdojo_external.slurm`](../scripts/run_agentdojo_external.slurm),
[`scripts/submit_agentdojo_external_wave.sh`](../scripts/submit_agentdojo_external_wave.sh),
and [`scripts/launch_vllm.sh`](../scripts/launch_vllm.sh). Compact publication files are:

- [`attempt_selection.json`](../artifacts/agentdojo-external-full-v1/attempt_selection.json)
- [`results_summary.json`](../artifacts/agentdojo-external-full-analysis-v1/results_summary.json)
- [`attack_summary.csv`](../artifacts/agentdojo-external-full-analysis-v1/attack_summary.csv)
- [`clean_utility.csv`](../artifacts/agentdojo-external-full-analysis-v1/clean_utility.csv)
- [`publication figure`](../artifacts/agentdojo-external-full-analysis-v1/agentdojo_outcomes.png)

Raw vLLM logs, complete official traces, and the large flat record export remain
ignored; the analysis manifest still records the SHA-256 of every selected input
record.

## Scope and limitations

AgentDojo is an external transfer check, not a replacement for the project
synthetic provenance benchmark. It evaluates one local model, two official attack
families, and the two official defenses across four suites. It does not evaluate
the project's capability gateway, provenance sink checks, PACT-L2, hardened corpus,
or semantic information-flow claims. T1--T4 authority leakage and T5--T6
sensitive-value leakage must remain separate from these AgentDojo metrics.
