"""Channel wire contract for HDO remediation comments (docs/hdo-remediation-comments.md §4).

The four guarantees the feature exists to deliver, asserted through HTTP:

1. pseudonymous on the wire — no identity field ever appears in a response;
2. linkable within one remediation — same person, same pseudonym;
3. unlinkable across remediations — same person, unrelated pseudonyms;
4. the identity a consumer asserts is consumed, never echoed.

Plus the gates: bearer auth, the remediation's own visibility gate inherited by
its comments, and the refusal to let a channel token mint a MEDISAO_NATIVE
identity.

Runs against the standalone ``testapp`` stub host (see
``viper_channel/tests/testapp/`` and ``viper_channel/README.md``); skipped
under the default (medcrypt) settings module. The MedISAO-native comment
surface (session-authenticated, medisao views) has its own tests in
``medisao/tests/test_remediation_comments.py``.
"""

from urllib.parse import quote

from django.apps import apps
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

if not apps.is_installed("viper_channel.tests.testapp"):
    import pytest

    pytest.skip(
        "requires DJANGO_SETTINGS_MODULE=viper_channel.tests.testapp.standalone_settings",
        allow_module_level=True,
    )

from viper_channel.enums import TLP, PublishStatus
from viper_channel.models import (
    ChannelApiToken,
    CommentAuthorProvider,
    PseudonymSecret,
    Remediation,
    RemediationComment,
    RemediationCommentAuthor,
)
from viper_channel.tests.testapp.models import Device, Organization, Workspace


def _org(name):
    return Organization.objects.create(name=f"Org-{name}")


def _device(org, name, *, discoverable=True):
    ws = Workspace.objects.create(name=f"WS-{name}", organization=org)
    return Device.objects.create(
        device_name=name,
        workspace=ws,
        is_publicly_discoverable=discoverable,
    )


class ChannelCommentTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, "Vent")
        self.remediation = Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.PUBLISHED,
        )
        self.other_remediation = Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.PUBLISHED,
        )
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")
        self.url = reverse(
            "viper_channel:remediation-comments",
            kwargs={"remediation_id": self.remediation.id},
        )

    def tearDown(self):
        cache.clear()

    def _post(self, url=None, **payload):
        body = {
            "author_provider": "viper",
            "author_external_user_id": "viper-user-1",
            "body": "We tested this patch on our fleet; downtime estimate looks optimistic.",
        }
        body.update(payload)
        return self.client.post(
            url or self.url,
            body,
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self.raw}",
        )

    def _get(self, url=None, query=""):
        return self.client.get((url or self.url) + query, HTTP_AUTHORIZATION=f"Bearer {self.raw}")

    # ── auth ────────────────────────────────────────────────────────────────
    def test_requires_bearer_token(self):
        self.assertEqual(self.client.get(self.url).status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            self.client.post(self.url, {}, format="json").status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    # ── the write path ──────────────────────────────────────────────────────
    def test_post_returns_the_pseudonymous_shape_not_the_asserted_identity(self):
        resp = self._post()
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            set(resp.data.keys()),
            {"id", "remediation_id", "pseudonym", "body", "created_at"},
        )
        # The poster gets back what every other consumer sees — not an echo of
        # the identity it just asserted.
        self.assertNotIn("author_external_user_id", resp.data)
        self.assertNotIn("author_provider", resp.data)
        self.assertNotIn("viper-user-1", str(resp.data))
        self.assertEqual(str(resp.data["remediation_id"]), str(self.remediation.id))

    def test_channel_token_cannot_assert_medisao_native(self):
        resp = self._post(author_provider="medisao_native")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("author_provider", resp.data)
        self.assertFalse(RemediationComment.objects.exists())

    def test_blank_body_and_blank_user_id_rejected(self):
        self.assertEqual(self._post(body="   ").status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            self._post(author_external_user_id="").status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_oversized_body_rejected(self):
        self.assertEqual(self._post(body="x" * 10001).status_code, status.HTTP_400_BAD_REQUEST)

    # ── the pseudonym guarantees ────────────────────────────────────────────
    def test_same_person_same_remediation_shares_a_pseudonym(self):
        first = self._post(body="first").data["pseudonym"]
        second = self._post(body="second").data["pseudonym"]
        self.assertEqual(first, second)
        # ...and exactly one identity row backs both comments.
        self.assertEqual(RemediationCommentAuthor.objects.count(), 1)
        self.assertEqual(RemediationComment.objects.count(), 2)

    def test_different_people_get_different_pseudonyms(self):
        a = self._post(author_external_user_id="alice").data["pseudonym"]
        b = self._post(author_external_user_id="bob").data["pseudonym"]
        self.assertNotEqual(a, b)

    def test_same_person_different_remediation_is_unlinkable(self):
        here = self._post().data["pseudonym"]
        there = self._post(
            url=reverse(
                "viper_channel:remediation-comments",
                kwargs={"remediation_id": self.other_remediation.id},
            )
        ).data["pseudonym"]
        self.assertNotEqual(here, there)

    def test_the_secret_actually_keys_the_pseudonym(self):
        """Knowing every public input is not enough to reproduce a pseudonym.

        That is the difference between this and a bare hash, and it is what stops
        anyone who can enumerate an HDO's user roster from unmasking commenters
        by brute force (§2.3).
        """
        from viper_channel import pseudonyms

        published = self._post(author_external_user_id="alice").data["pseudonym"]
        secret = PseudonymSecret.objects.get()
        inputs = {
            "realm_key": secret.realm_key,
            "provider": CommentAuthorProvider.VIPER,
            "external_user_id": "alice",
            "remediation_id": self.remediation.pk,
        }
        # With the real secret it reproduces exactly...
        self.assertEqual(
            published,
            pseudonyms.derive_pseudonym(secret=bytes(secret.secret), **inputs),
        )
        # ...with any other key it does not, however complete the guess is.
        self.assertNotEqual(published, pseudonyms.derive_pseudonym(secret=b"\x00" * 32, **inputs))

    def test_identity_is_stored_but_never_on_the_wire(self):
        self._post(author_external_user_id="viper-user-42")
        author = RemediationCommentAuthor.objects.get()
        self.assertEqual(author.provider, CommentAuthorProvider.VIPER)
        self.assertEqual(author.external_user_id, "viper-user-42")
        self.assertEqual(author.consumer_id, self.token.pk)
        # v1 GLOBAL token: we genuinely do not know the hospital, so we record
        # no org rather than guessing one.
        self.assertIsNone(author.org_id)

        body = str(self._get().data)
        self.assertNotIn("viper-user-42", body)
        self.assertNotIn("medisao_native", body)

    # ── the read path ───────────────────────────────────────────────────────
    def test_list_shape_and_ordering(self):
        self._post(body="older")
        self._post(body="newer")
        resp = self._get()
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        rows = resp.data["results"]
        self.assertEqual([r["body"] for r in rows], ["newer", "older"])
        self.assertEqual(
            set(rows[0].keys()),
            {"id", "remediation_id", "pseudonym", "body", "created_at"},
        )

    def test_comments_are_shared_not_per_consumer(self):
        """Deliberate difference from Inquiry: a second consumer sees the whole
        conversation. The pseudonym protects the author, not restricted reads."""
        self._post()
        _, raw_two = ChannelApiToken.issue(consumer_name="OTHER")
        resp = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_two}")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 1)

    def test_since_filter_and_garbage_since(self):
        self._post(body="first")
        # urlencoded: a bare isoformat ends in "+00:00", and the "+" decodes to
        # a space in a query string, which parse_datetime then rejects as garbage.
        cutoff = quote(RemediationComment.objects.get().created_at.isoformat())
        self._post(body="second")
        resp = self._get(query=f"?since={cutoff}")
        self.assertEqual([r["body"] for r in resp.data["results"]], ["second"])
        self.assertEqual(
            self._get(query="?since=not-a-date").status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_comments_inherit_the_remediation_gate(self):
        self._post()
        for mutate, label in (
            (
                lambda: Remediation.objects.filter(pk=self.remediation.pk).update(status=PublishStatus.DRAFT),
                "draft",
            ),
            (
                lambda: Remediation.objects.filter(pk=self.remediation.pk).update(tlp=TLP.AMBER),
                "amber",
            ),
            (
                lambda: Device.objects.filter(pk=self.device.pk).update(is_publicly_discoverable=False),
                "opted out",
            ),
        ):
            with self.subTest(gate=label):
                self.remediation.refresh_from_db()
                before_status, before_tlp = (
                    self.remediation.status,
                    self.remediation.tlp,
                )
                mutate()
                self.assertEqual(self._get().status_code, status.HTTP_404_NOT_FOUND, label)
                self.assertEqual(self._post().status_code, status.HTTP_404_NOT_FOUND, label)
                # restore for the next sub-case
                Remediation.objects.filter(pk=self.remediation.pk).update(status=before_status, tlp=before_tlp)
                Device.objects.filter(pk=self.device.pk).update(is_publicly_discoverable=True)

    def test_unknown_remediation_404(self):
        url = reverse(
            "viper_channel:remediation-comments",
            kwargs={"remediation_id": "00000000-0000-0000-0000-000000000000"},
        )
        self.assertEqual(self._get(url=url).status_code, status.HTTP_404_NOT_FOUND)

    def test_remediation_payload_links_to_comments(self):
        resp = self.client.get(
            reverse(
                "viper_channel:channel-remediations",
                kwargs={"channel_id": self.device.id},
            ),
            HTTP_AUTHORIZATION=f"Bearer {self.raw}",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("comments_url", resp.data["results"][0])
        self.assertIn("/comments", resp.data["results"][0]["comments_url"])


class ChannelCommentRealmTestCase(APITestCase):
    """Realm scoping: which secret keys the HMAC, and what that implies."""

    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.hospital = _org("hospital")
        self.remediation = Remediation.objects.create(
            device=_device(self.mdm, "Vent"),
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.PUBLISHED,
        )
        self.url = reverse(
            "viper_channel:remediation-comments",
            kwargs={"remediation_id": self.remediation.id},
        )

    def tearDown(self):
        cache.clear()

    def _post_as(self, raw, user_id="u1"):
        return self.client.post(
            self.url,
            {
                "author_provider": "viper",
                "author_external_user_id": user_id,
                "body": "hi",
            },
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {raw}",
        )

    def test_v1_global_token_uses_a_consumer_realm(self):
        token, raw = ChannelApiToken.issue(consumer_name="VIPER")
        self._post_as(raw)
        secret = PseudonymSecret.objects.get()
        self.assertEqual(secret.realm_key, f"consumer:{token.pk}")
        self.assertEqual(secret.consumer_id, token.pk)
        self.assertIsNone(secret.org_id)

    def test_v2_hdo_scoped_token_uses_an_org_realm(self):
        """The v2 seam: the moment a token names an HDO, the realm (and so the
        secret, and so rotation granularity) becomes per-hospital — no schema or
        endpoint change, which is the whole point of the seam."""
        token, raw = ChannelApiToken.issue(
            consumer_name="VIPER",
            scope_type=ChannelApiToken.Scope.HDO,
            hdo_org=self.hospital,
        )
        self._post_as(raw)
        secret = PseudonymSecret.objects.get()
        self.assertEqual(secret.realm_key, f"org:{self.hospital.pk}")
        self.assertEqual(secret.org_id, self.hospital.pk)
        author = RemediationCommentAuthor.objects.get()
        self.assertEqual(author.org_id, self.hospital.pk)
        self.assertEqual(author.consumer_id, token.pk)

    def test_two_consumers_are_different_realms_for_the_same_user_id(self):
        """Two consumer apps asserting the same literal user id are not assumed
        to mean the same human — different realms, different pseudonyms."""
        _, raw_a = ChannelApiToken.issue(consumer_name="VIPER")
        _, raw_b = ChannelApiToken.issue(consumer_name="OTHER")
        a = self._post_as(raw_a, user_id="42").data["pseudonym"]
        b = self._post_as(raw_b, user_id="42").data["pseudonym"]
        self.assertNotEqual(a, b)
        self.assertEqual(PseudonymSecret.objects.count(), 2)

    def test_two_hdo_scoped_tokens_for_one_hospital_share_pseudonyms(self):
        """Same hospital, second token: same realm, so the person stays linkable
        on a remediation they already commented on."""
        _, raw_one = ChannelApiToken.issue(
            consumer_name="VIPER-1",
            scope_type=ChannelApiToken.Scope.HDO,
            hdo_org=self.hospital,
        )
        _, raw_two = ChannelApiToken.issue(
            consumer_name="VIPER-2",
            scope_type=ChannelApiToken.Scope.HDO,
            hdo_org=self.hospital,
        )
        first = self._post_as(raw_one, user_id="nurse-7").data["pseudonym"]
        second = self._post_as(raw_two, user_id="nurse-7").data["pseudonym"]
        self.assertEqual(first, second)
        self.assertEqual(PseudonymSecret.objects.count(), 1)
