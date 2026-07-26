from __future__ import annotations

import unittest

from agentsec.pact import (
    CapabilityManifest,
    PACTArgument,
    PACTAuthority,
    PACTCall,
    PACTGateway,
    PACTProvenance,
    TransformationRegistry,
)
from agentsec.pact_tool_gateway import PACTToolGateway
from agentsec.schemas import EventKind, WorldState
from agentsec.tools import ToolExecutor
from agentsec.world import AuditLog, MockWorld


ALICE = "alice@example.test"
BOB = "bob@example.test"


def make_gateway() -> PACTGateway:
    return PACTGateway(
        CapabilityManifest(
            tool="send_email",
            allowed_values={"recipient": (ALICE, BOB)},
        ),
        TransformationRegistry(),
    )


def make_call(
    recipient: str,
    recipient_provenance: PACTProvenance,
    *,
    content: str = "Status update",
    content_provenance: PACTProvenance | None = None,
    subject: str = "Status",
) -> PACTCall:
    content_provenance = content_provenance or PACTProvenance.user(content)
    return PACTCall(
        tool="send_email",
        arguments={
            "recipient": PACTArgument(
                name="recipient",
                role="recipient",
                value=recipient,
                provenance=recipient_provenance,
            ),
            "content": PACTArgument(
                name="content",
                role="content",
                value=content,
                provenance=content_provenance,
            ),
            "subject": PACTArgument(
                name="subject",
                role="subject",
                value=subject,
                provenance=PACTProvenance.user(subject),
            ),
        },
    )


def make_tool_gateway() -> tuple[PACTToolGateway, MockWorld, AuditLog]:
    world = MockWorld(WorldState())
    audit = AuditLog()
    executor = ToolExecutor(world, audit)
    return PACTToolGateway(make_gateway(), executor), world, audit


class PACTToolGatewayTests(unittest.TestCase):
    def test_capability_only_sends_external_allowlisted_bob_through_tool_executor(self) -> None:
        adapter, world, audit = make_tool_gateway()
        result = adapter.execute_send_email(
            make_call(BOB, PACTProvenance.external(BOB, source_id="email-evil")),
            case_id="external-bob-send",
            policy="capability_only",
        )

        self.assertEqual("capability_only", result.policy)
        self.assertTrue(result.capability_allowed)
        self.assertFalse(result.pact_allowed)
        self.assertTrue(result.enforced_allowed)
        self.assertTrue(result.executed)
        self.assertTrue(result.tool_ok)
        self.assertEqual("evt-000001", result.tool_event_id)
        self.assertEqual(1, result.outbox_count)
        self.assertEqual(BOB, world.snapshot().outbox[0].to)
        self.assertEqual(EventKind.WORLD_MUTATION, audit.events[0].event_kind)
        self.assertTrue(result.decision_log_sha256)

    def test_pact_blocks_external_allowlisted_bob_before_tool_executor(self) -> None:
        adapter, world, audit = make_tool_gateway()
        result = adapter.execute_send_email(
            make_call(BOB, PACTProvenance.external(BOB, source_id="email-evil")),
            case_id="external-bob-send",
            policy="pact",
        )

        self.assertEqual("pact", result.policy)
        self.assertTrue(result.capability_allowed)
        self.assertFalse(result.pact_allowed)
        self.assertFalse(result.enforced_allowed)
        self.assertFalse(result.executed)
        self.assertFalse(result.tool_ok)
        self.assertIsNone(result.tool_event_id)
        self.assertEqual(0, result.outbox_count)
        self.assertEqual((), world.snapshot().outbox)
        self.assertEqual((), audit.events)
        self.assertIn("authority", result.reason.lower())

    def test_pact_sends_user_selected_bob(self) -> None:
        adapter, world, audit = make_tool_gateway()
        result = adapter.execute_send_email(
            make_call(BOB, PACTProvenance.user(BOB)),
            case_id="user-bob-send",
            policy="pact",
        )

        self.assertTrue(result.capability_allowed)
        self.assertTrue(result.pact_allowed)
        self.assertTrue(result.enforced_allowed)
        self.assertTrue(result.executed)
        self.assertTrue(result.tool_ok)
        self.assertEqual(1, result.outbox_count)
        self.assertEqual(BOB, world.snapshot().outbox[0].to)
        self.assertEqual(1, len(audit.events))

    def test_pact_sends_external_content_without_treating_it_as_recipient_authority(self) -> None:
        adapter, world, audit = make_tool_gateway()
        body = "Instructions copied from the external email"
        result = adapter.execute_send_email(
            make_call(
                ALICE,
                PACTProvenance.user(ALICE),
                content=body,
                content_provenance=PACTProvenance.external(body, source_id="email-evil"),
            ),
            case_id="external-content-send",
            policy="pact",
        )

        self.assertTrue(result.capability_allowed)
        self.assertTrue(result.pact_allowed)
        self.assertTrue(result.enforced_allowed)
        self.assertTrue(result.executed)
        self.assertEqual(1, result.outbox_count)
        self.assertEqual(body, world.snapshot().outbox[0].body)
        self.assertEqual(1, len(audit.events))

    def test_public_decision_wrappers_expose_existing_policy_checks(self) -> None:
        gateway = make_gateway()
        call = make_call(BOB, PACTProvenance.external(BOB, source_id="email-evil"))

        capability_allowed, capability_reason = gateway.capability_decision(call)
        pact_allowed, transformed, pact_reason = gateway.pact_decision(call)

        self.assertTrue(capability_allowed)
        self.assertIn("allow-list", capability_reason)
        self.assertFalse(pact_allowed)
        self.assertFalse(transformed)
        self.assertIn("authority", pact_reason)


if __name__ == "__main__":
    unittest.main()
