"""P2 tests: channel subscribe/unsubscribe and remediation inquiries.

* PUT/DELETE /channels/{id}/subscribe — idempotent, self-scoped, 404 on
  non-channel subscribe.
* GET/POST /remediations/{id}/inquiries — the one inbound write; visible only
  through a published channel remediation; a consumer sees only its OWN
  inquiries; unpublished/other-channel remediations 404.

Runs against the standalone ``testapp`` stub host (see
``viper_channel/tests/testapp/`` and ``viper_channel/README.md``); skipped
under the default (medcrypt) settings module.
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
from viper_channel.models import (
    ChannelApiToken,
    ChannelSubscription,
    Inquiry,
    Remediation,
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


class SubscribeTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, "Vent")
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")
        self.url = reverse("viper_channel:channel-subscribe", kwargs={"channel_id": self.device.id})

    def tearDown(self):
        cache.clear()

    def _auth(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.raw}"}

    def test_put_is_idempotent(self):
        r1 = self.client.put(self.url, **self._auth())
        self.assertEqual(r1.status_code, status.HTTP_201_CREATED)
        r2 = self.client.put(self.url, **self._auth())
        self.assertEqual(r2.status_code, status.HTTP_200_OK)
        self.assertEqual(
            ChannelSubscription.objects.filter(consumer=self.token, device=self.device).count(),
            1,
        )
        self.assertEqual(r1.data["channel_id"], str(self.device.id))

    def test_subscribe_to_non_channel_404(self):
        hidden = _device(self.mdm, "Hidden", discoverable=False)
        url = reverse("viper_channel:channel-subscribe", kwargs={"channel_id": hidden.id})
        self.assertEqual(self.client.put(url, **self._auth()).status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_is_idempotent(self):
        self.client.put(self.url, **self._auth())
        r1 = self.client.delete(self.url, **self._auth())
        self.assertEqual(r1.status_code, status.HTTP_204_NO_CONTENT)
        # Deleting again (nothing there) is still 204.
        r2 = self.client.delete(self.url, **self._auth())
        self.assertEqual(r2.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ChannelSubscription.objects.filter(consumer=self.token).exists())

    def test_delete_only_removes_own_subscription(self):
        other_token, _ = ChannelApiToken.issue(consumer_name="OTHER")
        ChannelSubscription.objects.create(consumer=other_token, device=self.device)
        self.client.put(self.url, **self._auth())

        self.client.delete(self.url, **self._auth())

        # The other consumer's subscription survives.
        self.assertTrue(ChannelSubscription.objects.filter(consumer=other_token, device=self.device).exists())


class InquiryTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.mdm = _org("mdm")
        self.device = _device(self.mdm, "Vent")
        self.published = Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.PUBLISHED,
        )
        self.draft = Remediation.objects.create(
            device=self.device,
            author_org=self.mdm,
            tlp=TLP.CLEAR,
            status=PublishStatus.DRAFT,
        )
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")

    def tearDown(self):
        cache.clear()

    def _auth(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.raw}"}

    def _url(self, remediation):
        return reverse(
            "viper_channel:remediation-inquiries",
            kwargs={"remediation_id": remediation.id},
        )

    def test_post_creates_inquiry(self):
        resp = self.client.post(
            self._url(self.published),
            {"body": "When is the patch shipping?"},
            format="json",
            **self._auth(),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        inquiry = Inquiry.objects.get(remediation=self.published)
        self.assertEqual(inquiry.consumer, self.token)
        self.assertEqual(inquiry.status, "open")
        self.assertEqual(resp.data["body"], "When is the patch shipping?")

    def test_post_requires_body(self):
        resp = self.client.post(self._url(self.published), {"body": ""}, format="json", **self._auth())
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_rejects_oversized_body(self):
        resp = self.client.post(
            self._url(self.published),
            {"body": "x" * 10001},
            format="json",
            **self._auth(),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cannot_inquire_on_unpublished_remediation(self):
        resp = self.client.post(self._url(self.draft), {"body": "hi"}, format="json", **self._auth())
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(Inquiry.objects.filter(remediation=self.draft).exists())

    def test_list_returns_only_own_inquiries(self):
        Inquiry.objects.create(remediation=self.published, consumer=self.token, body="mine")
        other_token, _ = ChannelApiToken.issue(consumer_name="OTHER")
        Inquiry.objects.create(remediation=self.published, consumer=other_token, body="theirs")

        resp = self.client.get(self._url(self.published), **self._auth())
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        bodies = {i["body"] for i in resp.data["results"]}
        self.assertEqual(bodies, {"mine"})

    def test_response_is_read_only_from_consumer(self):
        # A consumer cannot set the MDM's answer by POSTing `response`/`status`.
        resp = self.client.post(
            self._url(self.published),
            {"body": "q", "response": "hacked", "status": "answered"},
            format="json",
            **self._auth(),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        inquiry = Inquiry.objects.get(remediation=self.published)
        self.assertEqual(inquiry.response, "")
        self.assertEqual(inquiry.status, "open")
