from __future__ import annotations

import unittest

from agentsec import demo


class DemoChoiceTests(unittest.TestCase):
    def test_prompt_capability_arm_has_readable_defense_choice(self) -> None:
        choices = getattr(demo, "DEFENSE_CHOICES", ())

        self.assertIn(
            ("Prompt + capability (no provenance)", "prompt_capability_only"),
            choices,
        )


if __name__ == "__main__":
    unittest.main()
