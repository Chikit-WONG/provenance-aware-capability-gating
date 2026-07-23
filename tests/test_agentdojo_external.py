import hashlib
import unittest

from pydantic import ValidationError

from agentsec.agentdojo_external import (
    AgentDojoFrozenManifest,
    AgentDojoPair,
    AgentDojoRunSpec,
    build_development_plan,
    build_formal_plan,
    canonical_pair,
    select_agentdojo_pairs,
    validate_agentdojo_plan,
)


def _candidates(count: int = 24) -> list[AgentDojoPair]:
    return [
        canonical_pair(f"user_{index % 8:02d}", f"injection_{index:02d}")
        for index in range(count)
    ]


class AgentDojoExternalTests(unittest.TestCase):
    def test_canonical_pair_uses_frozen_workspace_key(self) -> None:
        pair = canonical_pair("u1", "i2")
        key = "workspace:v1.2.2:u1:i2"
        self.assertEqual(pair.canonical_key, key)
        self.assertEqual(pair.canonical_sha256, hashlib.sha256(key.encode()).hexdigest())
        self.assertTrue(pair.runnable)

    def test_selection_is_order_independent_and_uses_three_passes(self) -> None:
        candidates = [
            canonical_pair("u1", "i1"),
            canonical_pair("u2", "i1"),
            canonical_pair("u3", "i3"),
            canonical_pair("u4", "i4"),
            canonical_pair("u5", "i5"),
            canonical_pair("u6", "i6"),
            canonical_pair("u7", "i7"),
            canonical_pair("u8", "i8"),
            canonical_pair("u9", "i9"),
            canonical_pair("u10", "i10"),
            canonical_pair("u11", "i11"),
            canonical_pair("u12", "i12"),
            canonical_pair("u13", "i13"),
            canonical_pair("u14", "i14"),
            canonical_pair("u15", "i15"),
            canonical_pair("u16", "i16"),
            canonical_pair("u17", "i17"),
            canonical_pair("u18", "i18"),
            canonical_pair("u19", "i19"),
            canonical_pair("u20", "i20"),
        ]
        selected = select_agentdojo_pairs(candidates)
        shuffled = select_agentdojo_pairs(list(reversed(candidates)))
        self.assertEqual([item.canonical_key for item in selected], [item.canonical_key for item in shuffled])
        self.assertEqual(len(selected), 18)
        self.assertNotEqual(selected[0].user_task_id, selected[1].user_task_id)
        self.assertNotEqual(selected[0].injection_task_id, selected[1].injection_task_id)
        self.assertEqual(len({item.user_task_id for item in selected[:2]}), 2)
        self.assertEqual(len({item.injection_task_id for item in selected[:2]}), 2)

    def test_selection_requires_eighteen_runnable_pairs(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 18 runnable AgentDojo pairs are required"):
            select_agentdojo_pairs(_candidates(17))

    def test_selection_rejects_duplicate_canonical_pairs(self) -> None:
        candidates = _candidates(18)
        candidates.append(candidates[0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            select_agentdojo_pairs(candidates)

    def test_matrix_counts_and_unique_run_ids(self) -> None:
        selected = select_agentdojo_pairs(_candidates(24))
        development, formal = selected[:2], selected[2:]
        development_plan = build_development_plan(development)
        formal_plan = build_formal_plan(formal)
        formal_attacked = [row for row in formal_plan if row.attack != "none"]
        formal_clean = [row for row in formal_plan if row.attack == "none"]
        self.assertEqual(len(formal_attacked), 64)
        self.assertLessEqual(len(formal_clean), 32)
        self.assertLessEqual(len(formal_attacked) + len(formal_clean), 96)
        self.assertEqual({row.attack for row in formal_attacked}, {"important_instructions", "tool_knowledge"})
        self.assertEqual({row.defense for row in formal_attacked}, {"none", "repeat_user_prompt"})
        self.assertEqual({row.attack for row in formal_clean}, {"none"})
        all_rows = (*development_plan, *formal_plan)
        self.assertEqual(len({row.run_id for row in all_rows}), len(all_rows))
        self.assertEqual({row.phase for row in development_plan}, {"development"})
        self.assertEqual({row.phase for row in formal_plan}, {"formal"})

    def test_formal_validator_rejects_duplicate_missing_and_added_cells(self) -> None:
        selected = select_agentdojo_pairs(_candidates(24))
        formal = selected[2:]
        rows = build_formal_plan(formal)
        validate_agentdojo_plan(rows, formal)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_agentdojo_plan([*rows, rows[0]], formal)
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_agentdojo_plan(rows[:-1], formal)
        added = AgentDojoRunSpec(
            phase="formal",
            user_task_id=formal[0].user_task_id,
            injection_task_id="not-a-selected-injection",
            attack="important_instructions",
            defense="none",
        )
        with self.assertRaisesRegex(ValueError, "unexpected|added|selected"):
            validate_agentdojo_plan([*rows, added], formal)

    def test_strict_frozen_models_reject_unknown_fields_and_are_immutable(self) -> None:
        with self.assertRaises(ValidationError):
            AgentDojoPair(
                canonical_key="k",
                canonical_sha256="h",
                user_task_id="u",
                injection_task_id="i",
                runnable=True,
                unexpected=True,
            )
        row = AgentDojoRunSpec(
            phase="formal",
            user_task_id="u",
            injection_task_id=None,
            attack="none",
            defense="none",
        )
        self.assertTrue(row.run_id.startswith("adj-"))
        with self.assertRaises(ValidationError):
            row.attack = "tool_knowledge"

    def test_manifest_requires_pinned_revision_and_hashes(self) -> None:
        manifest = AgentDojoFrozenManifest(
            agentdojo_commit="a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
            agentdojo_tag="v0.1.35",
            benchmark_version="v1.2.2",
            suite="workspace",
            source_sha256="a" * 64,
            config_sha256="b" * 64,
            development_pair_keys=("u1:i1", "u2:i2"),
            formal_pair_keys=("u3:i3",),
            development_plan_sha256="c" * 64,
            formal_plan_sha256="d" * 64,
            selected_pair_count=3,
            development_pair_count=2,
            formal_pair_count=1,
            formal_attacked_count=4,
            formal_clean_count=2,
            formal_total_count=6,
        )
        self.assertEqual(manifest.schema_version, "1")
        self.assertEqual(manifest.formal_total_count, 6)
        with self.assertRaises(ValidationError):
            AgentDojoFrozenManifest(
                agentdojo_commit="wrong",
                agentdojo_tag="v0.1.35",
                benchmark_version="v1.2.2",
                suite="workspace",
                source_sha256="a" * 64,
                config_sha256="b" * 64,
                development_pair_keys=(),
                formal_pair_keys=(),
                development_plan_sha256="c" * 64,
                formal_plan_sha256="d" * 64,
                selected_pair_count=0,
                development_pair_count=0,
                formal_pair_count=0,
                formal_attacked_count=0,
                formal_clean_count=0,
                formal_total_count=0,
            )


if __name__ == "__main__":
    unittest.main()
