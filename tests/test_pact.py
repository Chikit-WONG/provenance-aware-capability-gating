from __future__ import annotations

import base64
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


ALICE = "alice@example.test"
BOB = "bob@example.test"


def gateway() -> PACTGateway:
    return PACTGateway(
        CapabilityManifest(
            tool="send_email",
            allowed_values={"recipient": (ALICE, BOB)},
        ),
        TransformationRegistry(),
    )


def call(*arguments: PACTArgument) -> PACTCall:
    return PACTCall(tool="send_email", arguments={item.name: item for item in arguments})


class PACTCaseTests(unittest.TestCase):
    def test_capability_lookup_uses_argument_role_not_argument_name(self) -> None:
        gateway_with_alice_only = PACTGateway(
            CapabilityManifest(
                tool="send_email",
                allowed_values={"recipient": (ALICE,)},
            ),
            TransformationRegistry(),
        )
        malformed = call(
            PACTArgument(
                name="recipient",
                role="content",
                value=BOB,
                provenance=PACTProvenance.external(BOB, source_id="email-evil"),
            )
        )

        capability_allowed, reason = gateway_with_alice_only.capability_decision(malformed)

        self.assertTrue(capability_allowed)
        self.assertIn("allow-list", reason)

    def test_user_selected_alice_is_allowed_by_capability_and_pact(self) -> None:
        result = gateway().execute(
            call(
                PACTArgument(
                    name="recipient",
                    role="recipient",
                    value=ALICE,
                    provenance=PACTProvenance.user(ALICE),
                )
            ),
            case_id="user-alice",
        )
        self.assertTrue(result.capability_allowed)
        self.assertTrue(result.pact_allowed)
        self.assertTrue(result.executed)
        self.assertEqual(1, result.side_effect_count)
        self.assertTrue(result.decision_log_sha256)

    def test_external_bob_in_allowlist_is_authority_laundering_denied_by_pact(self) -> None:
        result = gateway().execute(
            call(
                PACTArgument(
                    name="recipient",
                    role="recipient",
                    value=BOB,
                    provenance=PACTProvenance.external(BOB, source_id="email-evil"),
                )
            ),
            case_id="external-bob-allowlisted",
        )
        self.assertTrue(result.capability_allowed)
        self.assertFalse(result.pact_allowed)
        self.assertFalse(result.executed)
        self.assertEqual(0, result.side_effect_count)
        self.assertIn("authority", result.reason.lower())
        self.assertEqual("external", result.arguments["recipient"]["provenance"]["authority"])

    def test_external_content_is_allowed_at_low_risk_content_role(self) -> None:
        result = gateway().execute(
            call(
                PACTArgument(
                    name="recipient",
                    role="recipient",
                    value=ALICE,
                    provenance=PACTProvenance.user(ALICE),
                ),
                PACTArgument(
                    name="content",
                    role="content",
                    value="External email text",
                    provenance=PACTProvenance.external("External email text", source_id="email-evil"),
                ),
            ),
            case_id="external-content",
        )
        self.assertTrue(result.capability_allowed)
        self.assertTrue(result.pact_allowed)
        self.assertTrue(result.executed)
        self.assertEqual(1, result.side_effect_count)

    def test_registered_base64_transform_preserves_trusted_provenance(self) -> None:
        encoded = base64.b64encode(ALICE.encode()).decode()
        registry = TransformationRegistry()
        registry.register("Base64Encode", ALICE, encoded, source_authority=PACTAuthority.USER)
        result = PACTGateway(
            CapabilityManifest(tool="send_email", allowed_values={"recipient": (encoded,)}),
            registry,
        ).execute(
            call(
                PACTArgument(
                    name="recipient",
                    role="recipient",
                    value=encoded,
                    provenance=PACTProvenance.registered_transform(
                        source_value=ALICE,
                        output_value=encoded,
                        transform_name="Base64Encode",
                        source_authority=PACTAuthority.USER,
                    ),
                )
            ),
            case_id="registered-base64",
        )
        self.assertTrue(result.capability_allowed)
        self.assertTrue(result.pact_allowed)
        self.assertTrue(result.executed)
        self.assertTrue(result.transformation_verified)
        self.assertEqual(1, result.side_effect_count)

    def test_unregistered_transform_is_not_accepted_as_provenance(self) -> None:
        encoded = base64.b64encode(ALICE.encode()).decode()
        result = PACTGateway(
            CapabilityManifest(tool="send_email", allowed_values={"recipient": (encoded,)}),
            TransformationRegistry(),
        ).execute(
            call(
                PACTArgument(
                    name="recipient",
                    role="recipient",
                    value=encoded,
                    provenance=PACTProvenance.registered_transform(
                        source_value=ALICE,
                        output_value=encoded,
                        transform_name="Base64Encode",
                        source_authority=PACTAuthority.USER,
                    ),
                )
            ),
            case_id="unregistered-base64",
        )
        self.assertFalse(result.pact_allowed)
        self.assertFalse(result.executed)
        self.assertEqual(0, result.side_effect_count)

    def test_forged_user_provenance_is_denied_for_high_trust_recipient(self) -> None:
        forged = PACTProvenance(
            authority=PACTAuthority.USER,
            source_id="forged-label",
            source_value_sha256="0" * 64,
            value_sha256="0" * 64,
            source_authority=PACTAuthority.EXTERNAL,
        )
        result = gateway().execute(
            call(
                PACTArgument(
                    name="recipient",
                    role="recipient",
                    value=BOB,
                    provenance=forged,
                )
            ),
            case_id="forged-user-bob",
        )

        self.assertTrue(result.capability_allowed)
        self.assertFalse(result.pact_allowed)
        self.assertFalse(result.executed)
        self.assertEqual(0, result.side_effect_count)
        self.assertIn("provenance", result.reason.lower())


if __name__ == "__main__":
    unittest.main()
