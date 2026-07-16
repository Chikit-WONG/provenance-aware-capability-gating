import tempfile
import unittest
from pathlib import Path

from agentsec.experiment import execute_run_plan, load_record
from agentsec.model_client import AssistantTurn, StubModelClient, ToolCall
from agentsec.runplan import build_formal_plan
from agentsec.scenarios import load_scenario, load_scenarios


def _benign_t1_responses():
    return [
        AssistantTurn(
            tool_calls=(
                ToolCall(
                    id="search",
                    name="search_emails",
                    arguments={"query": "quarterly review"},
                ),
            )
        ),
        AssistantTurn(
            tool_calls=(
                ToolCall(
                    id="read",
                    name="read_email",
                    arguments={"email_id": "email_t1_update"},
                ),
            )
        ),
        AssistantTurn(content="Tuesday at 10:00 in GZ-301."),
        AssistantTurn(content="Tuesday at 10:00 in GZ-301."),
    ]


class ExperimentExecutionTests(unittest.TestCase):
    def test_single_run_persists_and_resume_never_reexecutes(self):
        scenarios = load_scenarios()
        record = next(
            row
            for row in build_formal_plan(scenarios, {"model": "stub"})
            if row.scenario_id == "T1"
            and row.content_condition.value == "clean"
            and row.defense_arm.value == "full"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_model = StubModelClient(_benign_t1_responses())
            first = execute_run_plan(
                first_model,
                [record],
                [load_scenario("T1")],
                artifact_root=root,
            )
            self.assertEqual(first.executed_n, 1)
            self.assertEqual(first.valid_n, 1)
            stored = load_record(root / record.run_id / "attempt-0001")
            self.assertEqual(stored["run_id"], record.run_id)

            never_called = StubModelClient([])
            resumed = execute_run_plan(
                never_called,
                [record],
                [load_scenario("T1")],
                artifact_root=root,
                resume=True,
            )
            self.assertEqual(resumed.executed_n, 0)
            self.assertEqual(resumed.resumed_n, 1)
            self.assertEqual(never_called.requests, [])
            with self.assertRaises(FileExistsError):
                execute_run_plan(
                    never_called,
                    [record],
                    [load_scenario("T1")],
                    artifact_root=root,
                )


if __name__ == "__main__":
    unittest.main()
