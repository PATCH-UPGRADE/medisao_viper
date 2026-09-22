"""P0 model-layer tests for the ARPA-H / VIPER channel integration.

Covers the two things P0 must get right before any API exists:

* the **visibility choke points** — ``Device.objects.channels_for(token)``,
  ``Advisory.objects.channel_advisories(device, token)``,
  ``Remediation.objects.channel_remediations(device, token)`` — enforce opt-in +
  PUBLISHED + TLP:CLEAR/GREEN, so no future endpoint can widen access by
  forgetting a filter;
* the ``ChannelApiToken`` hash/mint/authenticate contract (secret never stored
  in the clear, inactive tokens rejected);
* the publish-time stamp on the DRAFT -> PUBLISHED transition.

Runs against the standalone ``testapp`` stub host — see
``viper_channel/tests/testapp/`` and ``viper_channel/README.md``. Skipped
entirely under the default (medcrypt) settings module, where the equivalent
coverage against the REAL host models (including the medcrypt-specific
org-licensing gate this stub deliberately omits) lives in
``medisao/tests/test_viper_visibility_backend.py``.
"""

from django.apps import apps
from django.core.cache import cache
from django.test import TestCase

if not apps.is_installed("viper_channel.tests.testapp"):
    import pytest

    pytest.skip(
        "requires DJANGO_SETTINGS_MODULE=viper_channel.tests.testapp.standalone_settings",
        allow_module_level=True,
    )

from viper_channel.enums import TLP, PublishStatus
from viper_channel.models import ChannelApiToken, Remediation, RemediationCategory
from viper_channel.tests.testapp.models import Advisory, Device, Organization, Workspace


def _org(name):
    return Organization.objects.create(name=f"Org-{name}")


def _device(org, name="Dev", *, discoverable=False, archived=False):
    ws = Workspace.objects.create(name=f"WS-{name}", organization=org)
    return Device.objects.create(
        device_name=name,
        workspace=ws,
        is_publicly_discoverable=discoverable,
        is_archived=archived,
    )


class ChannelsForTestCase(TestCase):
    """`Device.objects.channels_for` is the single listing choke point."""

    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        # A GLOBAL (v1) consumer token — identity must not narrow the set.
        self.token, _ = ChannelApiToken.issue(consumer_name="VIPER")

    def tearDown(self):
        cache.clear()

    def test_only_opted_in_devices_are_channels(self):
        opted_in = _device(self.mdm, "opted-in", discoverable=True)
        _device(self.mdm, "opted-out", discoverable=False)
        _device(self.mdm, "archived", discoverable=True, archived=True)

        channels = list(Device.objects.channels_for(self.token))

        self.assertEqual(channels, [opted_in])

    def test_global_token_sees_all_mdms(self):
        other_mdm = _org("mdm2")
        d1 = _device(self.mdm, "a", discoverable=True)
        d2 = _device(other_mdm, "b", discoverable=True)

        self.assertCountEqual(Device.objects.channels_for(self.token), [d1, d2])


class ChannelAdvisoriesTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, discoverable=True)
        self.other_device = _device(self.mdm, "other", discoverable=True)
        self.token, _ = ChannelApiToken.issue(consumer_name="VIPER")

    def _adv(self, tlp, status, device=None):
        return Advisory.objects.create(
            name="a",
            description="a",
            tlp=tlp,
            status=status,
            device=device if device is not None else self.device,
            author_org=self.mdm,
        )

    def test_only_published_clear_green_for_this_device(self):
        ok_clear = self._adv(TLP.CLEAR, PublishStatus.PUBLISHED)
        ok_green = self._adv(TLP.GREEN, PublishStatus.PUBLISHED)
        self._adv(TLP.AMBER, PublishStatus.PUBLISHED)  # too sensitive
        self._adv(TLP.CLEAR, PublishStatus.DRAFT)  # not published
        self._adv(TLP.CLEAR, PublishStatus.PUBLISHED, device=self.other_device)  # other channel

        visible = Advisory.objects.channel_advisories(self.device, self.token)

        self.assertCountEqual(visible, [ok_clear, ok_green])

    def test_global_bulletins_never_leak_into_a_channel(self):
        # author_org NULL, device NULL — a CISA-style bulletin. Must not appear.
        Advisory.objects.create(name="cisa", description="x", tlp=TLP.CLEAR, status=PublishStatus.PUBLISHED)
        self.assertEqual(list(Advisory.objects.channel_advisories(self.device, self.token)), [])

    def test_none_device_yields_nothing_not_global_bulletins(self):
        # A caller that fails to resolve a device must get [], never every
        # `device IS NULL` bulletin across all orgs.
        Advisory.objects.create(name="cisa", description="x", tlp=TLP.CLEAR, status=PublishStatus.PUBLISHED)
        self.assertEqual(list(Advisory.objects.channel_advisories(None, self.token)), [])

    def test_opt_out_and_archive_hide_published_advisories(self):
        # Published CLEAR advisory on a currently-valid channel...
        adv = self._adv(TLP.CLEAR, PublishStatus.PUBLISHED)
        self.assertEqual(list(Advisory.objects.channel_advisories(self.device, self.token)), [adv])

        # ...disappears the moment the device is opted back out.
        self.device.is_publicly_discoverable = False
        self.device.save()
        self.assertEqual(list(Advisory.objects.channel_advisories(self.device, self.token)), [])

        # ...or archived.
        self.device.is_publicly_discoverable = True
        self.device.is_archived = True
        self.device.save()
        self.assertEqual(list(Advisory.objects.channel_advisories(self.device, self.token)), [])


class ChannelRemediationsTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, discoverable=True)
        self.token, _ = ChannelApiToken.issue(consumer_name="VIPER")

    def test_only_published_clear_green(self):
        ok = Remediation.objects.create(
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
        Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.DRAFT,
        )

        self.assertEqual(
            list(Remediation.objects.channel_remediations(self.device, self.token)),
            [ok],
        )

    def test_opt_out_hides_published_remediations(self):
        rem = Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.PUBLISHED,
        )
        self.assertEqual(
            list(Remediation.objects.channel_remediations(self.device, self.token)),
            [rem],
        )

        self.device.is_publicly_discoverable = False
        self.device.save()
        self.assertEqual(list(Remediation.objects.channel_remediations(self.device, self.token)), [])
        self.assertEqual(list(Remediation.objects.channel_remediations(None, self.token)), [])


class PublishStampTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, discoverable=True)

    def test_published_at_set_once_on_transition(self):
        adv = Advisory.objects.create(
            name="a",
            description="a",
            tlp=TLP.CLEAR,
            status=PublishStatus.DRAFT,
            device=self.device,
        )
        self.assertIsNone(adv.published_at)

        adv.status = PublishStatus.PUBLISHED
        adv.save()
        first_stamp = adv.published_at
        self.assertIsNotNone(first_stamp)

        # Re-saving a published advisory must not move the stamp.
        adv.description = "edited"
        adv.save()
        self.assertEqual(adv.published_at, first_stamp)

    def test_remediation_publish_stamp(self):
        rem = Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            category=RemediationCategory.VENDOR_FIX,
        )
        self.assertIsNone(rem.published_at)
        rem.status = PublishStatus.PUBLISHED
        rem.save()
        self.assertIsNotNone(rem.published_at)


class ChannelApiTokenTestCase(TestCase):
    def test_issue_returns_raw_once_and_stores_only_hash(self):
        token, raw = ChannelApiToken.issue(consumer_name="VIPER")

        self.assertTrue(raw)
        # The clear-text secret is never persisted.
        self.assertNotEqual(token.token_hash, raw)
        self.assertEqual(token.token_hash, ChannelApiToken._hash(raw))
        self.assertEqual(token.token_prefix, raw[:8])
        self.assertEqual(token.scope_type, ChannelApiToken.Scope.GLOBAL)

    def test_authenticate_roundtrip(self):
        token, raw = ChannelApiToken.issue(consumer_name="VIPER")
        resolved = ChannelApiToken.authenticate(raw)
        self.assertEqual(resolved, token)
        resolved.refresh_from_db()
        self.assertIsNotNone(resolved.last_seen_at)

    def test_authenticate_rejects_bad_and_inactive(self):
        token, raw = ChannelApiToken.issue(consumer_name="VIPER")
        self.assertIsNone(ChannelApiToken.authenticate("not-a-real-token"))
        self.assertIsNone(ChannelApiToken.authenticate(""))
        self.assertIsNone(ChannelApiToken.authenticate(None))

        token.is_active = False
        token.save()
        self.assertIsNone(ChannelApiToken.authenticate(raw))
