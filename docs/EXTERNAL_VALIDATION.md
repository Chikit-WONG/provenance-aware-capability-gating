# Native AgentDojo external validation

## Status

This workstream is **implementation-complete but execution-blocked**. The
native AgentDojo plans and results are intentionally absent: the pinned
pre-inference freeze did not run, so no native pair IDs, victim calls, attack
rates, or utility numbers are reported here.

## Frozen contract (when the prerequisite is available)

- AgentDojo: `v0.1.35`, exact source commit
  `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`.
- Benchmark: Workspace `v1.2.2`.
- Attacks: official `important_instructions` and `tool_knowledge`.
- Defenses: official `none` and `repeat_user_prompt`.
- Victim: the existing local checkpoint
  `/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct`, served as `qwen3-vl-8b`.
- Runtime: temperature `0.0`, JSON tool output, local non-streaming vLLM, no
  external services.

The freeze enumerates the public Workspace suite and screens both official
attacks before inference. It sorts by the canonical pair hash and applies the
three fixed diversity passes, selecting 18 runnable pairs: two development
pairs and 16 formal pairs. The intended formal matrix is 64 attacked cells
(two attacks x two defenses x 16 pairs) plus at most 32 clean cells (one clean
cell per selected user task and defense), for at most 96 victim calls. Selection
is independent of model responses.

## Official scoring boundary

AgentDojo's task environments, attack constructors, defense pipeline, user-task
evaluator, and injection-task evaluator remain untouched. The only compatibility
registration is `qwen3-vl-8b -> Qwen`, needed by the official attack
constructor. Official security values and utility values are retained as
separate metrics; they are not translated into the project's gateway labels.
Native results would support claims about this local Qwen victim and the
official `repeat_user_prompt` defense only. They would not evaluate or validate
this project's `Full` gateway.

## Attempts and artifacts

Execution uses append-only `attempt-0001` records. A single `attempt-0002` is
permitted only for a declared infrastructure failure (timeout, local endpoint
transport failure, scheduler termination, or artifact-write interruption).
Behavioral failures, refusals, no-ops, parse failures, failed attacks, and
blocked calls are never retried.

The reviewed launcher is [`scripts/run_agentdojo_external.slurm`](../scripts/run_agentdojo_external.slurm), and bounded waves are submitted with
[`scripts/submit_agentdojo_external_wave.sh`](../scripts/submit_agentdojo_external_wave.sh).
They fail closed if the official plans are missing. No files under
`configs/frozen/agentdojo_external_v1/`, `artifacts/agentdojo-external-v1/`,
or `artifacts/agentdojo-external-analysis-v1/` were fabricated or substituted
from the project's older frozen plans.

## Why execution is blocked

The first bootstrap attempt failed while Conda contacted the configured
Tsinghua mirror (`SSLEOFError`/`CondaSSLError`). A temporary official Conda
channel override did create Python 3.11, but installing the exact VCS pin still
failed: the cluster's GitHub clone path returned HTTP 403 (and the Conda git
runtime had a `libffi`/`libp11-kit` symbol conflict); codeload/API archives
were truncated by the network proxy. The PyPI `agentdojo==0.1.35` wheel was
not substituted because it has no VCS `direct_url.json` proving the required
commit. Consequently the official freeze could not produce selected IDs or a
manifest, no development job was submitted, the four-hour development gate was
not started, and the formal Task 7 execution/analysis was skipped.

Once the exact VCS environment and network path are available, run the freeze
and verification commands in the AgentDojo plan, then submit development before
formal waves. The project-specific benchmark and existing attack results remain
separate from this external-validation workstream.
