import unittest

from agentsec.pressure import run_sink_pressure_cases


class SinkPressureTests(unittest.TestCase):
    def test_all_four_sink_cases_isolate_provenance_blocking(self) -> None:
        rows = run_sink_pressure_cases()

        self.assertEqual(16, len(rows))
        self.assertTrue(all(row["passed"] for row in rows))
        for row in rows:
            expected_execution = row["defense_arm"] in {
                "capability_only",
                "prompt_capability_only",
            }
            self.assertEqual(expected_execution, row["execution_ok"])
            self.assertEqual(
                ("deploy-token",) if not expected_execution else (),
                tuple(row["detected_taints"]),
            )


if __name__ == "__main__":
    unittest.main()
