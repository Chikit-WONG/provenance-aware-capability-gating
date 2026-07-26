import unittest

from agentsec.agentdojo_guard import AgentDojoGate


class AgentDojoGateTests(unittest.TestCase):
    def test_capability_blocks_untrusted_recipient(self) -> None:
        gate = AgentDojoGate("capability_only")
        gate.observe_messages(
            [
                {"role": "user", "content": "Send the report to alice@example.com."},
                {"role": "tool", "content": "alice@example.com"},
            ]
        )
        allowed, reason = gate.evaluate(
            "send_email",
            {"recipients": ["mallory@example.com"], "subject": "report", "body": "ok"},
        )
        self.assertFalse(allowed)
        self.assertIn("recipient", reason)

    def test_capability_allows_user_authorized_recipient(self) -> None:
        gate = AgentDojoGate("capability_only")
        gate.observe_messages(
            [{"role": "user", "content": "Send the report to alice@example.com."}]
        )
        allowed, reason = gate.evaluate(
            "send_email",
            {"recipients": ["alice@example.com"], "subject": "report", "body": "ok"},
        )
        self.assertTrue(allowed, reason)

    def test_provenance_blocks_exact_tool_derived_secret_at_sink(self) -> None:
        gate = AgentDojoGate("provenance_only")
        gate.observe_messages([{"role": "user", "content": "Find the status."}])
        gate.observe_tool_output("get_file_by_id", {"content": "SYNTHETIC-TOKEN-12345"})
        allowed, reason = gate.evaluate(
            "send_email",
            {"recipients": ["alice@example.com"], "subject": "status", "body": "SYNTHETIC-TOKEN-12345"},
        )
        self.assertFalse(allowed)
        self.assertIn("provenance", reason)

    def test_non_sink_read_is_not_blocked_by_provenance(self) -> None:
        gate = AgentDojoGate("provenance_only")
        gate.observe_tool_output("get_file_by_id", {"content": "SYNTHETIC-TOKEN-12345"})
        allowed, reason = gate.evaluate("get_file_by_id", {"file_id": "file-1"})
        self.assertTrue(allowed, reason)

    def test_full_combines_capability_and_provenance(self) -> None:
        gate = AgentDojoGate("full")
        gate.observe_messages([{"role": "user", "content": "Send it to alice@example.com."}])
        gate.observe_tool_output("read_file", {"content": "SYNTHETIC-TOKEN-12345"})
        allowed, reason = gate.evaluate(
            "send_email",
            {"recipients": ["alice@example.com"], "subject": "x", "body": "SYNTHETIC-TOKEN-12345"},
        )
        self.assertFalse(allowed)
        self.assertIn("provenance", reason)


if __name__ == "__main__":
    unittest.main()
