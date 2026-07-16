from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentsec.conditions import (
    CONDITION_PLACEHOLDER,
    materialize_condition,
    resolve_payload,
)
from agentsec.scenarios import EXPECTED_SCENARIO_IDS, load_scenarios, validate_scenario
from agentsec.schemas import ContentCondition


class ScenarioConditionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scenarios = load_scenarios()

    def test_complete_suite_loads_in_registered_order(self) -> None:
        self.assertEqual(
            tuple(scenario.scenario_id for scenario in self.scenarios),
            EXPECTED_SCENARIO_IDS,
        )

    def test_each_scenario_has_matched_conditions_and_one_placeholder(self) -> None:
        for scenario in self.scenarios:
            with self.subTest(scenario=scenario.scenario_id):
                self.assertEqual(
                    set(scenario.condition_payloads), set(ContentCondition)
                )
                self.assertEqual(
                    scenario.initial_world.model_dump_json().count(CONDITION_PLACEHOLDER),
                    1,
                )
                lengths = [len(value) for value in scenario.condition_payloads.values()]
                self.assertLessEqual(max(lengths) / min(lengths), 1.25)

    def test_materialization_is_exact_and_does_not_mutate_spec(self) -> None:
        scenario = self.scenarios[0]
        original = scenario.initial_world.model_dump_json()
        target_id = "email_t1_update"

        for condition in ContentCondition:
            with self.subTest(condition=condition.value):
                world = materialize_condition(scenario, condition)
                body = world.emails[target_id].body
                self.assertNotIn(CONDITION_PLACEHOLDER, body)
                self.assertIn(scenario.condition_payloads[condition], body)

        self.assertEqual(scenario.initial_world.model_dump_json(), original)
        self.assertIn(CONDITION_PLACEHOLDER, scenario.initial_world.emails[target_id].body)

    def test_invalid_condition_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            materialize_condition(self.scenarios[0], "not-a-condition")

    def test_missing_placeholder_is_rejected(self) -> None:
        scenario = self.scenarios[0]
        email = scenario.initial_world.emails["email_t1_update"]
        changed_email = email.model_copy(
            update={"body": email.body.replace(CONDITION_PLACEHOLDER, "")}
        )
        emails = dict(scenario.initial_world.emails)
        emails[email.email_id] = changed_email
        changed_world = scenario.initial_world.model_copy(update={"emails": emails})
        changed_scenario = scenario.model_copy(update={"initial_world": changed_world})
        with self.assertRaisesRegex(ValueError, "exactly one condition placeholder"):
            validate_scenario(changed_scenario)

    def test_all_registered_protected_literals_exist_in_initial_world(self) -> None:
        for scenario in self.scenarios:
            serialized = scenario.initial_world.model_dump_json()
            for protected in scenario.protected_values:
                with self.subTest(
                    scenario=scenario.scenario_id, protected=protected.protected_id
                ):
                    self.assertIn(protected.value, serialized)

    def test_file_payload_references_are_confined_to_base_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.txt").write_text("frozen payload", encoding="utf-8")
            self.assertEqual(
                resolve_payload("file:payload.txt", base_dir=root), "frozen payload"
            )
            with self.assertRaisesRegex(ValueError, "escapes"):
                resolve_payload("file:../outside.txt", base_dir=root)


if __name__ == "__main__":
    unittest.main()

