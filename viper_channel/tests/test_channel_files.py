"""Remediation artifact download (VIPER-facing) + the token-mint command.

Closes two end-to-end gaps: VIPER can now see + download a remediation's files,
and there is a supported way to mint the bearer token VIPER authenticates with.

Runs against the standalone ``testapp`` stub host (see
``viper_channel/tests/testapp/`` and ``viper_channel/README.md``);
``RemediationFileDownloadTestCase`` is skipped under the default (medcrypt)
settings module. ``MintTokenCommandTestCase`` needs no Device/Organization
fixtures — just ``ChannelApiToken`` — so it carries the same guard purely for
consistency (every class in this file shares one settings-dependent module).
"""

import tempfile
from io import StringIO
from pathlib import Path

from django.apps import apps
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
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
from viper_channel.models import ChannelApiToken, Remediation, RemediationFile
from viper_channel.tests.testapp.models import Device, Organization, Workspace


def _org(name):
    return Organization.objects.create(name=f"Org-{name}")


def _device(org, discoverable=True):
    ws = Workspace.objects.create(name="WS", organization=org)
    return Device.objects.create(
        device_name="Vent",
        workspace=ws,
        is_publicly_discoverable=discoverable,
    )


class MintTokenCommandTestCase(TestCase):
    def test_mint_creates_authenticatable_token(self):
        out = StringIO()
        call_command("mint_channel_token", "VIPER", stdout=out)
        output = out.getvalue()

        token = ChannelApiToken.objects.get(consumer_name="VIPER")
        self.assertTrue(token.is_active)
        self.assertIn(token.token_prefix, output)
        # The raw token is printed once; find it (the long word that starts with
        # the prefix) and confirm it authenticates back to this row.
        raw = next(
            w
            for line in output.splitlines()
            for w in [line.strip()]
            if w.startswith(token.token_prefix) and len(w) > 20
        )
        self.assertEqual(ChannelApiToken.authenticate(raw), token)


@override_settings(SHARED_DATA_DIR=tempfile.mkdtemp())
class RemediationFileDownloadTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.org = _org("acme")
        self.device = _device(self.org)
        self.remediation = Remediation.objects.create(
            device=self.device,
            author_org=self.org,
            tlp=TLP.CLEAR,
            status=PublishStatus.PUBLISHED,
        )
        self.token, self.raw = ChannelApiToken.issue(consumer_name="VIPER")

        from django.conf import settings

        self.file_path = Path(settings.SHARED_DATA_DIR) / "patch.txt"
        self.file_path.write_bytes(b"firmware patch notes")
        self.rf = RemediationFile.objects.create(
            remediation=self.remediation,
            name="patch.txt",
            file_path=str(self.file_path),
            content_type="text/plain",
            size_bytes=20,
        )

    def tearDown(self):
        cache.clear()

    def _url(self, remediation=None, file_id=None):
        return reverse(
            "viper_channel:channel-remediation-file",
            kwargs={
                "channel_id": self.device.id,
                "remediation_id": (remediation or self.remediation).id,
                "file_id": file_id or self.rf.id,
            },
        )

    def test_remediation_lists_file_with_download_url(self):
        resp = self.client.get(
            reverse(
                "viper_channel:channel-remediations",
                kwargs={"channel_id": self.device.id},
            ),
            HTTP_AUTHORIZATION=f"Bearer {self.raw}",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        files = resp.data["results"][0]["files"]
        self.assertEqual(len(files), 1)
        self.assertIn("download_url", files[0])
        self.assertEqual(files[0]["name"], "patch.txt")

    def test_download_streams_as_attachment_with_nosniff(self):
        resp = self.client.get(self._url(), HTTP_AUTHORIZATION=f"Bearer {self.raw}")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("attachment", resp["Content-Disposition"])
        self.assertEqual(resp["X-Content-Type-Options"], "nosniff")
        self.assertEqual(b"".join(resp.streaming_content), b"firmware patch notes")

    def test_download_requires_auth(self):
        self.assertEqual(self.client.get(self._url()).status_code, status.HTTP_401_UNAUTHORIZED)

    def test_unpublished_remediation_file_404(self):
        self.remediation.status = PublishStatus.DRAFT
        self.remediation.save()
        resp = self.client.get(self._url(), HTTP_AUTHORIZATION=f"Bearer {self.raw}")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
