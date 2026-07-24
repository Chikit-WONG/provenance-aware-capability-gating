# Related work and project positioning

This project is a controlled, course-scale evaluation of deterministic
capability gating and exact protected-value egress checks. It is not presented
as the first provenance or capability system for LLM agents. The frozen study
predates the optional `pact_l2` implementation described below; historical
results retain their original defense labels.

## Closest mechanism

### PACT: argument-level provenance contracts

L. Fan et al., "The Granularity Mismatch in Agent Security: Argument-Level
Provenance Solves Enforcement and Isolates the LLM Reasoning Bottleneck,"
arXiv:2605.11039, 2026.
[Paper](https://arxiv.org/abs/2605.11039)

PACT is the closest conceptual reference. It treats indirect prompt injection
as unsafe authority binding: external content may fill a message body but must
not determine a recipient, command, credential, or other authority-bearing
argument. Its L0-L3 hierarchy separates opaque invocation checks, capability
checks, argument-role contracts, and scoped trusted discharge.

Project mapping:

- the frozen capability arms are closest to PACT L1;
- exact protected-value scanning is a narrow credential-egress rule over
  content fields, not general provenance;
- the post-study `pact_l2` arm adds schema-complete role contracts, a trust
  lattice, conservative origin merging, and fail-closed resolution;
- automatic contract synthesis, semantic provenance inference, and scoped
  discharge certificates remain out of scope.

## Information-flow and isolation systems

### FIDES

M. Costa et al., "Securing AI Agents with Information-Flow Control,"
arXiv:2505.23643, 2025.
[Paper](https://arxiv.org/abs/2505.23643)

FIDES motivates the separation between confidentiality and integrity labels and
characterizes what dynamic taint tracking can enforce. The project's independent
`sensitivity` and `authority` dimensions follow the same general information-
flow discipline, but the frozen implementation recognizes only registered exact
protected values rather than arbitrary derived information.

### CaMeL

E. Debenedetti et al., "Defeating Prompt Injections by Design,"
arXiv:2503.18813, 2025.
[Paper](https://arxiv.org/abs/2503.18813)

CaMeL separates control flow derived from the trusted user request from data
flow containing untrusted tool outputs, and uses capabilities to constrain
exfiltration. It is a stronger quarantine-style architecture than this
project's ordinary agent loop. The comparison clarifies the trade-off between
restricting replanning and mediating the resulting arguments at runtime.

### Progent

T. Shi et al., "Progent: Programmable Privilege Control for LLM Agents,"
arXiv:2504.11703, 2025.
[Paper](https://arxiv.org/abs/2504.11703)

Progent supplies a policy language for least privilege, deterministic runtime
enforcement, fallback actions, and monotonic policy updates checked with SMT.
The project's static scenario capability manifest plays a similar role but is
treated as a correct oracle. Automatic policy generation and approved privilege
expansion are not evaluated here.

## Evaluation methodology

### AgentSecBench

F. Alpay and T. Alpay, "AgentSecBench: Measuring Prompt Injection, Privacy
Leakage, and Tool-Use Integrity in LLM Agents," arXiv:2605.26269, 2026.
[Paper](https://arxiv.org/abs/2605.26269)

AgentSecBench distinguishes instruction integrity, retrieval confidentiality,
and capability integrity, and uses paired benign controls plus exact markers to
obtain unambiguous observations. It is especially close to this project's use
of synthetic secrets, matched placebos, capability/provenance ablations, and
narrow claims about exact-value leakage.

### AgentDojo and InjecAgent

E. Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate Prompt
Injection Attacks and Defenses for LLM Agents," NeurIPS 2024.
[Paper](https://arxiv.org/abs/2406.13352)

Q. Zhan et al., "InjecAgent: Benchmarking Indirect Prompt Injections in
Tool-Integrated Large Language Model Agents," ACL Findings 2024.
[Paper](https://arxiv.org/abs/2403.02691)

These benchmarks provide broader task and attack coverage. The repository's
AgentDojo adapter derives capability manifests from benchmark ground truth and
therefore measures an oracle upper bound, not deployable policy inference.

### Adaptive evaluation

X. Ma et al., "AutoDojo: Adaptive Attacks Expose Superficial Defenses and
User-Underspecification Limits in LLM Agents," arXiv:2606.15057, 2026.
[Paper](https://arxiv.org/abs/2606.15057)

AutoDojo shows why robustness to frozen injections should not be interpreted as
robustness to an adaptive adversary, and distinguishes fully specified,
parameter-open, and action-open tasks. This project's frozen payloads support
reproducibility and causal comparisons; adaptive robustness is explicitly a
separate follow-up question.

## Defensible project claim

The supported claim is:

> Given a correct task-authorization manifest, deterministic capability gating
> and exact registered-value egress checks reduce executed indirect-prompt-
> injection effects in a controlled local office-agent environment, with
> measurable utility cost.

The optional PACT-L2 extension supports mechanism tests about argument
granularity and cross-step origin preservation. It does not retroactively turn
the frozen study into a full PACT evaluation or establish general semantic
non-interference.
