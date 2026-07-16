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

## Exclusions and responsible research

- no real user, credential, account, service, or personal data;
- no unauthorized access, scraping, disruption, persistence, or evasion of host
  controls;
- no arbitrary shell, network, deletion, payment, or privilege-escalation tool;
- no claim that exact-literal tracking stops encoding, paraphrase, splitting,
  steganography, or unknown sensitive values;
- no claim that results from one local 8B model generalize to all agents.

