# Threat model

## System boundary

The protected system begins at the trusted user request and ends at local mock
tool state. It includes the Reader Agent, Action Agent, orchestration code,
immutable scenario manifest, provenance tracker, capability gateway, mock tools,
and audit log. The model server is trusted to return bytes faithfully but the
model's decisions are not trusted as a security boundary.

## Assets and security properties

1. **Confidentiality:** registered `secret` and non-declassified `internal`
   values must not reach an unauthorized outbox recipient or public sink.
2. **Integrity:** external email content must not cause a tool/resource/action or
   parameter value outside the user's task capability.
3. **Availability/utility:** the defense should preserve the task's benign state
   predicates and avoid blocking authorized calls.
4. **Evidence integrity:** an outcome must be attributable to structured reads,
   proposals, policy decisions, executions, and state changes.

## Adversary

The attacker controls one task-relevant inbound email body or attachment text,
knows the public tool schemas and defense category, and can use an offline Red
Agent to craft the text. The attacker aims to cause an unauthorized state change
or exact synthetic-secret exfiltration.

The attacker cannot modify the original user request, system prompt, scenario
manifest, provenance metadata, gateway, evaluator, model weights, mock world
outside the carrier, or runtime configuration. The core evaluation is not an
online adaptive attack: formal payloads are frozen before victim runs.

## Trust and labels

Authority and confidentiality are independent dimensions:

- authority: `trusted_system`, `trusted_user`, `untrusted_external`, `derived`;
- sensitivity: `public`, `internal`, `secret`.

Only the orchestrator assigns labels and event parents. Natural-language claims
such as "approved by admin" cannot change authority. Derived strings inherit
parents conservatively. The prototype recognizes exact registered protected
values in proposed outbound arguments.

## Capability oracle

The main experiment uses the scenario manifest as a correct authorization oracle.
Capabilities constrain tool, resource, recipients/participants, parameter bounds,
call count, and permitted outbound sensitivity. Automatically inferring correct
capabilities from natural language is outside scope and would confound the
security evaluation.

## Position within related work

The prototype sits between invocation-level and argument-level enforcement, in
the terminology of argument-level provenance contracts (PACT,
arXiv:2605.11039): capability gating is an L1-style capability check, while the
exact protected-value sink check is a credential-egress rule over `content`-role
arguments (see "Argument-level trust model" in ARCHITECTURE.md).  Compared with
quarantine architectures such as CaMeL (arXiv:2503.18813) and IFC systems such
as FIDES (arXiv:2505.23643), the prototype does not propagate taint through
arbitrary dataflow; compared with programmable privilege control (Progent,
arXiv:2504.11703) and provable defenses (MELON, arXiv:2502.05174), its policy
is static per scenario.  Its distinguishing evaluation discipline is
state-based outcome derivation (world-state diffs, not LLM judges), frozen
hashed plans and corpora, matched placebos, and intention-to-test accounting.

The optional `pact_l2` arm is a post-study mechanism extension, not a relabeling
of the frozen `full` arm. It adds fail-closed role-specific trust checks and
cross-step origin accumulation for explicitly observed or declared values.
Because its resolver is structural rather than semantic, its guarantee is
conditional on conservative registration of transformations. Its results must
be stored and reported separately from every existing frozen experiment.

## Exclusions and responsible research

- no real user, credential, account, service, or personal data;
- no unauthorized access, scraping, disruption, persistence, or evasion of host
  controls;
- no arbitrary shell, network, deletion, payment, or privilege-escalation tool;
- no claim that exact-literal tracking stops encoding, paraphrase, splitting,
  steganography, or unknown sensitive values;
- no claim that results from one local 8B model generalize to all agents.
