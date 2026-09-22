"""P1 read-API tests for the ARPA-H/VIPER channel integration.

Asserts the wire contract end-to-end through the HTTP layer:

* bearer auth (missing / malformed / invalid / inactive token);
* opt-in + TLP + PUBLISHED gating on channel listing and per-channel reads;
* cross-tenant isolation (a token sees every opted-in channel — open discovery
  by design — but never DRAFT / AMBER+ / non-discoverable content);
* ``?since=`` incremental sync and its 400 on garbage input.

Runs against the standalone ``testapp`` stub host (see
``viper_channel/tests/testapp/`` and ``viper_channel/README.md``); skipped
under the default (medcrypt) settings module. The ``Advisory.objects.visible_to``
cross-tenant leak regression (a medisao-specific general advisory-visibility
concept unrelated to the channel API) lives in
``medisao/tests/test_advisory_visibility_regression.py`` instead.
"""

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
from viper_channel.models import ChannelApiToken, Remediation
from viper_channel.tests.testapp.models import Advisory, Device, Organization, Workspace


def _org(name):
    return Organization.objects.create(name=f"Org-{name}")


def _device(org, name, *, discoverable=True):
    ws = Workspace.objects.create(name=f"WS-{name}", organization=org)
    return Device.objects.create(
        device_name=name,
        workspace=ws,
        is_publicly_discoverable=discoverable,
    )


class ChannelAuthTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        _device(self.mdm, "d1")
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")
        self.url = reverse("viper_channel:channel-list")

    def tearDown(self):
        cache.clear()

    def test_missing_token_denied(self):
        # No credentials + a WWW-Authenticate challenge (authenticate_header) -> 401.
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_malformed_header_401(self):
        resp = self.client.get(self.url, HTTP_AUTHORIZATION="Bearer")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_invalid_token_401(self):
        resp = self.client.get(self.url, HTTP_AUTHORIZATION="Bearer nope-nope-nope")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_inactive_token_401(self):
        self.token.is_active = False
        self.token.save()
        resp = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {self.raw}")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_valid_token_ok(self):
        resp = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {self.raw}")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)


class ChannelListTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.mdm_a = _org("a")
        self.mdm_b = _org("b")
        self.d_a = _device(self.mdm_a, "AlphaVent")
        self.d_b = _device(self.mdm_b, "BetaPump")
        _device(self.mdm_a, "SecretDev", discoverable=False)  # opted out
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")

    def tearDown(self):
        cache.clear()

    def _get(self, url):
        return self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {self.raw}")

    def test_lists_only_opted_in_channels_all_tenants(self):
        # Open discovery: one token sees both MDMs' opted-in channels...
        resp = self._get(reverse("viper_channel:channel-list"))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        ids = {c["id"] for c in resp.data["results"]}
        self.assertEqual(ids, {str(self.d_a.id), str(self.d_b.id)})

    def test_channel_shape(self):
        resp = self._get(reverse("viper_channel:channel-list"))
        channel = next(c for c in resp.data["results"] if c["id"] == str(self.d_a.id))
        self.assertEqual(channel["vendor"], self.mdm_a.name)
        self.assertEqual(channel["product"], "AlphaVent")
        self.assertIn("updated_at", channel)

    def test_manufacturer_id_filter(self):
        url = reverse("viper_channel:channel-list") + f"?manufacturer_id={self.mdm_a.id}"
        resp = self._get(url)
        ids = {c["id"] for c in resp.data["results"]}
        self.assertEqual(ids, {str(self.d_a.id)})

    def test_since_rejects_garbage(self):
        resp = self._get(reverse("viper_channel:channel-list") + "?since=not-a-date")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_manufacturer_id_rejects_non_uuid(self):
        resp = self._get(reverse("viper_channel:channel-list") + "?manufacturer_id=garbage")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class ChannelAdvisoryReadTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, "Vent")
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")
        self.url = reverse("viper_channel:channel-advisories", kwargs={"channel_id": self.device.id})

    def tearDown(self):
        cache.clear()

    def _adv(self, tlp, status_, name="a"):
        return Advisory.objects.create(
            name=name,
            description=name,
            tlp=tlp,
            status=status_,
            device=self.device,
            author_org=self.mdm,
        )

    def _get(self, url):
        return self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {self.raw}")

    def test_only_published_clear_green(self):
        self._adv(TLP.CLEAR, PublishStatus.PUBLISHED, "pub-clear")
        self._adv(TLP.GREEN, PublishStatus.PUBLISHED, "pub-green")
        self._adv(TLP.AMBER, PublishStatus.PUBLISHED, "pub-amber")
        self._adv(TLP.CLEAR, PublishStatus.DRAFT, "draft")

        resp = self._get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        names = {a["name"] for a in resp.data["results"]}
        self.assertEqual(names, {"pub-clear", "pub-green"})

    def test_non_channel_device_404(self):
        opted_out = _device(self.mdm, "Hidden", discoverable=False)
        url = reverse("viper_channel:channel-advisories", kwargs={"channel_id": opted_out.id})
        self.assertEqual(self._get(url).status_code, status.HTTP_404_NOT_FOUND)

    def test_since_incremental(self):
        old = self._adv(TLP.CLEAR, PublishStatus.PUBLISHED, "old")
        Advisory.objects.filter(pk=old.pk).update(updated_at="2020-01-01T00:00:00Z")
        self._adv(TLP.CLEAR, PublishStatus.PUBLISHED, "new")

        resp = self._get(self.url + "?since=2021-01-01T00:00:00Z")
        names = {a["name"] for a in resp.data["results"]}
        self.assertEqual(names, {"new"})


class ChannelRemediationReadTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, "Vent")
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")
        self.url = reverse("viper_channel:channel-remediations", kwargs={"channel_id": self.device.id})

    def tearDown(self):
        cache.clear()

    def test_only_published_clear_green(self):
        Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.PUBLISHED,
        )
        Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.AMBER,
            status=PublishStatus.PUBLISHED,
        )
        resp = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {self.raw}")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 1)
        self.assertEqual(resp.data["results"][0]["tlp"], TLP.CLEAR)
        self.assertEqual(resp.data["results"][0]["inquiries"], 0)
