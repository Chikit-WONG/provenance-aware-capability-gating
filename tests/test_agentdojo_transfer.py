import unittest

from agentsec.agentdojo_external import (
    TRANSFER_DEFENSES,
    AgentDojoRunSpec,
    build_transfer_plan_from_rows,
)


class AgentDojoTransferTests(unittest.TestCase):
    def test_transfer_defenses_are_explicit(self) -> None:
        self.assertEqual(
            TRANSFER_DEFENSES,
            (
                "none",
                "repeat_user_prompt",
                "capability_only",
                "provenance_only",
                "prompt_capability",
                "prompt_provenance",
                "full",
            ),
        )

    def test_transfer_plan_expands_one_baseline_cell_per_defense(self) -> None:
        baseline = [
            AgentDojoRunSpec(
                suite="workspace",
                phase="formal",
                user_task_id="user_task_1",
                injection_task_id="injection_task_1",
                attack="important_instructions",
                defense="none",
                model_config_hash="e" * 64,
            ),
            AgentDojoRunSpec(
                suite="workspace",
                phase="formal",
                user_task_id="user_task_1",
                injection_task_id=None,
                attack="none",
                defense="none",
                model_config_hash="e" * 64,
            ),
        ]
        expanded = build_transfer_plan_from_rows(baseline)
        self.assertEqual(len(expanded), len(TRANSFER_DEFENSES) * 2)
        self.assertEqual(
            {row.defense for row in expanded}, set(TRANSFER_DEFENSES)
        )
        self.assertEqual(
            len({row.run_id for row in expanded}), len(expanded)
        )


if __name__ == "__main__":
    unittest.main()
