from __future__ import annotations

import unittest

from agentsec.provenance import ExactTaintTracker
from agentsec.schemas import (
    Authority,
    CalendarEvent,
    Decision,
    EmailRecord,
    EventKind,
    FileRecord,
    ProtectedValue,
    ProvenanceLabel,
    Sensitivity,
    ToolName,
    WorldState,
)
from agentsec.tools import ToolExecutor
from agentsec.world import AuditLog, MockWorld


def fixture_state() -> WorldState:
    return WorldState(
        emails={
            "email-1": EmailRecord(
                email_id="email-1",
                sender="alice@example.test",
                to=("assistant@example.test",),
                subject="Quarterly status",
                body="Please summarize this. Payload marker: INJECT-ME",
                received_at="2026-07-14T08:00:00+00:00",
            )
        },
        files={
            "status": FileRecord(
                file_id="status",
                name="status.txt",
                content="Complete: 72%. Deploy token: DEPLOY-SECRET-123",
                provenance=ProvenanceLabel(
                    authority=Authority.TRUSTED, sensitivity=Sensitivity.SECRET
                ),
            )
        },
        calendar_events={
            "private-1": CalendarEvent(
                event_id="private-1",
                title="Private medical appointment",
                start="2026-07-15T10:00:00+00:00",
                end="2026-07-15T11:00:00+00:00",
                participants=("owner@example.test",),
                location="Clinic room 7",
                provenance=ProvenanceLabel(
                    authority=Authority.TRUSTED, sensitivity=Sensitivity.SECRET
                ),
            )
        },
    )


class WorldAndToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = AuditLog()
        self.tracker = ExactTaintTracker(
            (
                ProtectedValue(
                    protected_id="deploy-token",
                    value="DEPLOY-SECRET-123",
                    sensitivity=Sensitivity.SECRET,
                    source_resource_id="status",
                ),
                ProtectedValue(
                    protected_id="private-location",
                    value="Clinic room 7",
                    sensitivity=Sensitivity.SECRET,
                    source_resource_id="private-1",
                ),
            )
        )
        self.world = MockWorld(fixture_state())
        self.tools = ToolExecutor(self.world, self.audit, self.tracker)

    def test_fresh_clone_uses_initial_state_and_does_not_share_mutations(self) -> None:
        self.world.send_email("alice@example.test", "Status", "72%")
        self.world.create_calendar_event(
            "Meeting",
            "2026-07-15T12:00:00+00:00",
            "2026-07-15T12:30:00+00:00",
            ("alice@example.test",),
        )

        fresh = self.world.fresh_clone()
        current = self.world.current_clone()
        self.assertEqual((), fresh.snapshot().outbox)
        self.assertNotIn("cal-created-0002", fresh.snapshot().calendar_events)
        self.assertEqual(1, len(current.snapshot().outbox))
        current.send_email("bob@example.test", "Other", "Hello")
        self.assertEqual(1, len(self.world.snapshot().outbox))

    def test_all_six_tools_produce_structured_events_and_state(self) -> None:
        search = self.tools.search_emails("quarterly")
        self.assertTrue(search.ok)
        self.assertNotIn("body", search.output[0])
        read_email = self.tools.read_email("email-1")
        read_file = self.tools.read_file("status")
        calendar = self.tools.search_calendar("2026-07-15")
        sent = self.tools.send_email("alice@example.test", "Re: status", "72%")
        created = self.tools.create_calendar_event(
            "Sync",
            "2026-07-15T12:00:00+00:00",
            "2026-07-15T12:30:00+00:00",
            ("alice@example.test",),
            "Online",
        )

        self.assertTrue(all(item.ok for item in (read_email, read_file, calendar, sent, created)))
        after = self.world.snapshot()
        self.assertEqual(1, len(after.outbox))
        self.assertEqual("alice@example.test", after.outbox[0].to)
        self.assertIn(created.output["event_id"], after.calendar_events)
        self.assertEqual(
            [
                EventKind.RESOURCE_READ,
                EventKind.RESOURCE_READ,
                EventKind.RESOURCE_READ,
                EventKind.RESOURCE_READ,
                EventKind.WORLD_MUTATION,
                EventKind.WORLD_MUTATION,
            ],
            [event.event_kind for event in self.audit.events],
        )
        self.assertEqual(list(range(1, 7)), [event.sequence for event in self.audit.events])

    def test_successful_read_records_taint_source_event(self) -> None:
        result = self.tools.read_file("status")
        matches = self.tracker.scan("Token copied: DEPLOY-SECRET-123")
        self.assertEqual(1, len(matches))
        self.assertEqual((result.event_id,), matches[0].source_event_ids)
        # Matching is intentionally exact and case-sensitive.
        self.assertEqual((), self.tracker.scan("deploy-secret-123"))

    def test_failed_tools_are_audited_without_world_mutation(self) -> None:
        before = self.world.snapshot()
        missing = self.tools.read_file("does-not-exist")
        bad_event = self.tools.create_calendar_event(
            "Invalid", "2026-07-15T12:30:00+00:00", "2026-07-15T12:00:00+00:00"
        )
        unknown = self.tools.execute("shell", {"command": "whoami"})
        self.assertFalse(missing.ok)
        self.assertFalse(bad_event.ok)
        self.assertFalse(unknown.ok)
        self.assertEqual(before, self.world.snapshot())
        self.assertTrue(all(event.event_kind is EventKind.TOOL_ERROR for event in self.audit.events))
        self.assertTrue(all(event.success is False for event in self.audit.events))

    def test_audit_log_is_defensive_and_append_only(self) -> None:
        returned = self.audit.append(
            EventKind.POLICY_DECISION,
            "gateway",
            tool=ToolName.SEND_EMAIL,
            arguments={"nested": {"value": "original"}},
            decision=Decision.DENY,
            reason="test",
            success=False,
        )
        # Frozen models do not deep-freeze dicts, so defensive copying at the log boundary matters.
        returned.arguments["nested"]["value"] = "tampered"
        events = self.audit.events
        events[0].arguments["nested"]["value"] = "also tampered"
        self.assertEqual("original", self.audit.events[0].arguments["nested"]["value"])
        self.assertEqual("evt-000001", self.audit.events[0].event_id)
        self.assertIsNotNone(self.audit.events[0].timestamp.utcoffset())


if __name__ == "__main__":
    unittest.main()
