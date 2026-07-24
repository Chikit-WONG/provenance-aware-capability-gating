# Secret Broker

## Security goal

Capability checks answer whether an agent may perform an operation. They do not
prevent a model that has already seen a password or token from reproducing,
encoding, splitting, or logging it.

`agentsec.secrets.SecretBroker` therefore enforces a separate rule: registered
secret plaintext does not cross the trusted executor-to-model boundary.

```text
trusted world / secret store
          |
          | plaintext
          v
    SecretBroker  -- secret://deploy-token --> model
          ^
          | purpose-bound redemption
          |
   trusted consumer only
```

Opaque references are not bearer credentials. A reference can be redeemed only
by a registered consumer, before its expiry, and within its use limit. Scenario
registrations grant no consumer by default.

## Runtime behavior

When `ExperimentOrchestrator(secret_broker_enabled=True)` is used:

1. `Sensitivity.SECRET` protected values are registered in a fresh broker for
   each attempt.
2. Successful tool outputs are recursively tokenized before they enter Reader
   or Action Agent messages.
3. Model-produced plaintext and references are removed from stored normalized
   turns.
4. The secret firewall runs before every capability-defense branch, including
   `allow_all`, and denies secret-bearing external tool calls.
5. Audit arguments, final responses, and completed Reader/Action traces contain
   `[REDACTED_SECRET]`, not plaintext or usable references.

The switch defaults to `False`, so historical frozen plans and published
results retain their original semantics.

## Purpose-bound redemption

Deployment integrations may explicitly grant a trusted consumer:

```python
from agentsec.secrets import SecretBroker

broker = SecretBroker()
reference = broker.register(
    "deploy-token",
    token_from_vault,
    allowed_consumers=("deployment-service",),
    max_uses=1,
)

# This call belongs inside trusted executor code, never Agent code.
token = broker.redeem(reference, consumer="deployment-service")
```

Knowing or guessing `secret://deploy-token` is insufficient to redeem it.
Unauthorized, expired, unknown, and exhausted references fail closed.

## Boundary

The mock world's authoritative snapshots still contain synthetic ground-truth
values because the evaluator needs them. Those snapshots belong to the trusted
server-side artifact boundary and must not be exposed as model context. A real
deployment should source plaintext from an external vault and encrypt or omit
server-side snapshots.

The prototype detects registered exact literals before they enter the model. It
does not discover previously unknown secrets or protect values that were never
registered.
