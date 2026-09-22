"""Pseudonym derivation: determinism, unlinkability, injectivity.

Pure logic against ``viper_channel.pseudonyms`` — no host models, no medisao
dependency. See docs/hdo-remediation-comments.md for the broader design; the
comment endpoints that build on this live host-side (`medisao/tests/`)
because that's where the comment surface itself is implemented.
"""

from django.test import TestCase

from viper_channel import pseudonyms
from viper_channel.models import ChannelApiToken


class PseudonymDerivationTestCase(TestCase):
    """Unit-level properties of the derivation, independent of any endpoint."""

    def setUp(self):
        self.secret = pseudonyms.new_secret()
        self.base = {
            "secret": self.secret,
            "realm_key": "org:abc",
            "provider": "medisao_native",
            "external_user_id": "7",
            "remediation_id": "r-1",
        }

    def test_deterministic(self):
        self.assertEqual(
            pseudonyms.derive_pseudonym(**self.base),
            pseudonyms.derive_pseudonym(**self.base),
        )

    def test_every_input_changes_the_output(self):
        baseline = pseudonyms.derive_pseudonym(**self.base)
        for field, other in (
            ("realm_key", "org:def"),
            ("provider", "viper"),
            ("external_user_id", "8"),
            ("remediation_id", "r-2"),
        ):
            with self.subTest(field=field):
                self.assertNotEqual(baseline, pseudonyms.derive_pseudonym(**{**self.base, field: other}))
        self.assertNotEqual(
            baseline,
            pseudonyms.derive_pseudonym(**{**self.base, "secret": pseudonyms.new_secret()}),
        )

    def test_components_cannot_be_confused_by_concatenation(self):
        """``("1", "23")`` and ``("12", "3")`` must not collide.

        Plain concatenation would collapse two different people into one
        pseudonym; the length prefixes are what prevent it.
        """
        a = pseudonyms.derive_pseudonym(**{**self.base, "external_user_id": "1", "remediation_id": "23"})
        b = pseudonyms.derive_pseudonym(**{**self.base, "external_user_id": "12", "remediation_id": "3"})
        self.assertNotEqual(a, b)

    def test_realm_key_follows_the_token_scope(self):
        global_token = ChannelApiToken(consumer_name="VIPER")
        global_token.pk = "11111111-1111-1111-1111-111111111111"
        self.assertEqual(pseudonyms.realm_key_for_token(global_token), f"consumer:{global_token.pk}")

        scoped = ChannelApiToken(consumer_name="VIPER")
        scoped.pk = "22222222-2222-2222-2222-222222222222"
        scoped.hdo_org_id = "33333333-3333-3333-3333-333333333333"
        self.assertEqual(pseudonyms.realm_key_for_token(scoped), f"org:{scoped.hdo_org_id}")
