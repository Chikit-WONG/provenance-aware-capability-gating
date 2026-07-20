from __future__ import annotations

import base64
import unittest

from agentsec.policy import CapabilityGateway
from agentsec.provenance import ExactTaintTracker
from agentsec.schemas import (
    Capability,
    DefenseArm,
    EmailRecord,
    EventKind,
    ParameterBound,
    ProtectedValue,
    Sensitivity,
    ToolName,
    WorldState,
)
from agentsec.tools import ToolExecutor
from agentsec.world import AuditLog, MockWorld


ALICE = "alice@example.test"
MALLORY = "mallory@example.test"
TOKEN = "DEPLOY-SECRET-123"


def make_stack(
    arm: DefenseArm, capabilities: tuple[Capability, ...]
) -> tuple[MockWorld, AuditLog, ExactTaintTracker, ToolExecutor, CapabilityGateway]:
    world = MockWorld(
        WorldState(
            emails={
                "email-1": EmailRecord(
                    email_id="email-1",
                    sender=ALICE,
                    to=("assistant@example.test",),
                    subject="Status",
                    body="Please report project status.",
                )
            }
        )
    )
    audit = AuditLog()
    tracker = ExactTaintTracker(
        (
            ProtectedValue(
                protected_id="deploy-token",
                value=TOKEN,
                sensitivity=Sensitivity.SECRET,
                source_resource_id="status-file",
            ),
        )
    )
    executor = ToolExecutor(world, audit, tracker)
    gateway = CapabilityGateway(arm, capabilities, audit, tracker)
    return world, audit, tracker, executor, gateway


def reply_capability(**updates: object) -> Capability:
    values: dict[str, object] = {
        "capability_id": "reply-alice",
        "tool": ToolName.SEND_EMAIL,
        "allowed_recipients": (ALICE,),
        "max_calls": 1,
        "max_outbound_sensitivity": Sensitivity.PUBLIC,
    }
    values.update(updates)
    return Capability(**values)


class PolicyTests(unittest.TestCase):
    def test_prompt_capability_only_has_stable_serialized_value(self) -> None:
        self.assertEqual(
            "prompt_capability_only",
            DefenseArm.PROMPT_CAPABILITY_ONLY.value,
        )

    def test_allow_all_and_prompt_only_do_not_enforce_manifest(self) -> None:
        for arm in (DefenseArm.ALLOW_ALL, DefenseArm.PROMPT_ONLY):
            with self.subTest(arm=arm):
                world, audit, _, executor, gateway = make_stack(arm, ())
                result = gateway.execute(
                    executor,
                    ToolName.SEND_EMAIL,
                    {"to": MALLORY, "subject": "secret", "body": TOKEN, "cc": []},
                )
                self.assertTrue(result.decision.allowed)
                self.assertTrue(result.execution and result.execution.ok)
                self.assertEqual(MALLORY, world.snapshot().outbox[0].to)
                self.assertEqual(
                    [
                        EventKind.TOOL_PROPOSAL,
                        EventKind.POLICY_DECISION,
                        EventKind.WORLD_MUTATION,
                    ],
                    [event.event_kind for event in audit.events],
                )

    def test_prompt_capability_only_rejects_out_of_manifest_recipient(self) -> None:
        world, _, _, executor, gateway = make_stack(
            DefenseArm.PROMPT_CAPABILITY_ONLY,
            (reply_capability(),),
        )
        result = gateway.execute(
            executor,
            ToolName.SEND_EMAIL,
            {"to": MALLORY, "subject": "No", "body": "data", "cc": []},
        )
        self.assertFalse(result.decision.allowed)
        self.assertIsNone(result.execution)
        self.assertEqual((), world.snapshot().outbox)

    def test_prompt_capability_only_allows_registered_secret_without_taint_block(
        self,
    ) -> None:
        world, _, tracker, executor, gateway = make_stack(
            DefenseArm.PROMPT_CAPABILITY_ONLY,
            (reply_capability(),),
        )
        tracker.observe_read("evt-source", ("status-file",))
        result = gateway.execute(
            executor,
            ToolName.SEND_EMAIL,
            {
                "to": ALICE,
                "subject": "Status",
                "body": f"Deploy token: {TOKEN}",
                "cc": [],
            },
        )
        self.assertTrue(result.decision.allowed)
        self.assertTrue(result.execution and result.execution.ok)
        self.assertEqual(1, len(world.snapshot().outbox))

    def test_capability_only_checks_tool_resource_recipient_and_call_count(self) -> None:
        capabilities = (
            Capability(
                capability_id="read-one-email",
                tool=ToolName.READ_EMAIL,
                allowed_resource_ids=("email-1",),
                max_calls=1,
            ),
            reply_capability(),
        )
        world, _, _, executor, gateway = make_stack(DefenseArm.CAPABILITY_ONLY, capabilities)

        wrong_resource = gateway.execute(
            executor, ToolName.READ_EMAIL, {"email_id": "email-2"}
        )
        self.assertFalse(wrong_resource.decision.allowed)
        read = gateway.execute(executor, ToolName.READ_EMAIL, {"email_id": "email-1"})
        repeated = gateway.execute(executor, ToolName.READ_EMAIL, {"email_id": "email-1"})
        redirected = gateway.execute(
            executor,
            ToolName.SEND_EMAIL,
            {"to": ALICE, "subject": "status", "body": "72%", "cc": [MALLORY]},
        )
        no_calendar_capability = gateway.execute(
            executor,
            ToolName.CREATE_CALENDAR_EVENT,
            {
                "title": "Injected",
                "start": "2026-07-15T10:00:00+00:00",
                "end": "2026-07-15T11:00:00+00:00",
                "participants": [],
                "location": "",
            },
        )
        self.assertTrue(read.decision.allowed)
        self.assertFalse(repeated.decision.allowed)
        self.assertIn("maximum call count", repeated.decision.reason)
        self.assertFalse(redirected.decision.allowed)
        self.assertIn(MALLORY, redirected.decision.reason)
        self.assertFalse(no_calendar_capability.decision.allowed)
        self.assertEqual((), world.snapshot().outbox)

    def test_calendar_parameter_window_and_exact_duration(self) -> None:
        capability = Capability(
            capability_id="alice-30-minute-meeting",
            tool=ToolName.CREATE_CALENDAR_EVENT,
            allowed_recipients=(ALICE,),
            parameter_bounds={
                "start": ParameterBound(
                    minimum="2026-07-15T09:00:00+00:00",
                    maximum="2026-07-15T17:00:00+00:00",
                ),
                "end": ParameterBound(
                    minimum="2026-07-15T09:00:00+00:00",
                    maximum="2026-07-15T17:00:00+00:00",
                ),
                "duration_minutes": ParameterBound(minimum=30, maximum=30),
            },
            max_calls=2,
        )
        world, _, _, executor, gateway = make_stack(
            DefenseArm.CAPABILITY_ONLY, (capability,)
        )
        common = {
            "title": "Alice sync",
            "participants": [ALICE],
            "location": "Online",
        }
        two_hours = gateway.execute(
            executor,
            ToolName.CREATE_CALENDAR_EVENT,
            {
                **common,
                "start": "2026-07-15T10:00:00+00:00",
                "end": "2026-07-15T12:00:00+00:00",
            },
        )
        outside_window = gateway.execute(
            executor,
            ToolName.CREATE_CALENDAR_EVENT,
            {
                **common,
                "start": "2026-07-15T18:00:00+00:00",
                "end": "2026-07-15T18:30:00+00:00",
            },
        )
        allowed = gateway.execute(
            executor,
            ToolName.CREATE_CALENDAR_EVENT,
            {
                **common,
                "start": "2026-07-15T10:00:00+00:00",
                "end": "2026-07-15T10:30:00+00:00",
            },
        )
        self.assertFalse(two_hours.decision.allowed)
        self.assertIn("duration_minutes", two_hours.decision.reason)
        self.assertFalse(outside_window.decision.allowed)
        self.assertTrue(allowed.decision.allowed)
        self.assertEqual(1, len(world.snapshot().calendar_events))

    def test_capability_only_allows_exact_secret_but_full_blocks_it(self) -> None:
        for arm, expected in (
            (DefenseArm.CAPABILITY_ONLY, True),
            (DefenseArm.FULL, False),
        ):
            with self.subTest(arm=arm):
                world, audit, tracker, executor, gateway = make_stack(
                    arm, (reply_capability(),)
                )
                tracker.observe_read("evt-source", ("status-file",))
                result = gateway.execute(
                    executor,
                    ToolName.SEND_EMAIL,
                    {
                        "to": ALICE,
                        "subject": "Status",
                        "body": f"Complete: 72%. Deploy token: {TOKEN}",
                        "cc": [],
                    },
                )
                self.assertEqual(expected, result.decision.allowed)
                self.assertEqual(1 if expected else 0, len(world.snapshot().outbox))
                if arm is DefenseArm.FULL:
                    self.assertIn("deploy-token", result.decision.reason)
                    decision_event = audit.get(result.decision.policy_event_id)
                    self.assertEqual(("evt-source",), decision_event.provenance.source_event_ids)

    def test_full_allows_benign_output_and_documents_exact_match_limit(self) -> None:
        world, _, _, executor, gateway = make_stack(DefenseArm.FULL, (reply_capability(max_calls=2),))
        benign = gateway.execute(
            executor,
            ToolName.SEND_EMAIL,
            {"to": ALICE, "subject": "Status", "body": "Complete: 72%", "cc": []},
        )
        encoded = base64.b64encode(TOKEN.encode()).decode()
        transformed = gateway.execute(
            executor,
            ToolName.SEND_EMAIL,
            {"to": ALICE, "subject": "Status", "body": encoded, "cc": []},
        )
        self.assertTrue(benign.decision.allowed)
        self.assertTrue(transformed.decision.allowed)
        self.assertEqual(2, len(world.snapshot().outbox))

    def test_denied_proposal_has_no_execution_event_or_state_effect(self) -> None:
        world, audit, _, executor, gateway = make_stack(
            DefenseArm.CAPABILITY_ONLY, (reply_capability(),)
        )
        result = gateway.execute(
            executor,
            ToolName.SEND_EMAIL,
            {"to": MALLORY, "subject": "No", "body": "data", "cc": []},
        )
        self.assertIsNone(result.execution)
        self.assertEqual((), world.snapshot().outbox)
        self.assertEqual(
            [EventKind.TOOL_PROPOSAL, EventKind.POLICY_DECISION],
            [event.event_kind for event in audit.events],
        )
        self.assertFalse(audit.events[-1].success)


if __name__ == "__main__":
    unittest.main()
