"""P6: the channel API must appear correctly in the published OpenAPI schema
(the integration contract VIPER builds against).

Runs against the standalone ``testapp`` stub host's own urlconf (see
``viper_channel/tests/testapp/urls.py``), rather than the real
``public_api.v1.urls`` mount — that mount is medcrypt-specific routing
(viper_channel's URLs included alongside every other public_api endpoint),
not something the portable app can depend on. Skipped under the default
(medcrypt) settings module; the equivalent assertion against the REAL mount
lives in ``public_api``'s own schema tests.
"""

from django.apps import apps
from django.test import TestCase

if not apps.is_installed("viper_channel.tests.testapp"):
    import pytest

    pytest.skip(
        "requires DJANGO_SETTINGS_MODULE=viper_channel.tests.testapp.standalone_settings",
        allow_module_level=True,
    )

from drf_spectacular.generators import SchemaGenerator


class ChannelSchemaTestCase(TestCase):
    def setUp(self):
        generator = SchemaGenerator(urlconf="viper_channel.tests.testapp.urls")
        self.schema = generator.get_schema(request=None, public=True)

    def test_channel_paths_present(self):
        paths = self.schema["paths"]
        for expected in (
            "/api/public/v1/channels",
            "/api/public/v1/channels/{channel_id}/advisories",
            "/api/public/v1/channels/{channel_id}/remediations",
            "/api/public/v1/channels/{channel_id}/subscribe",
            "/api/public/v1/remediations/{remediation_id}/inquiries",
        ):
            self.assertIn(expected, paths, f"{expected} missing from OpenAPI schema")

    def test_bearer_security_scheme_documented(self):
        schemes = self.schema["components"]["securitySchemes"]
        self.assertIn("ChannelApiToken", schemes)
        self.assertEqual(schemes["ChannelApiToken"]["scheme"], "bearer")

    def test_channel_list_declares_security(self):
        # The channel list operation must require the bearer credential.
        get_op = self.schema["paths"]["/api/public/v1/channels"]["get"]
        security_schemes = {key for entry in get_op.get("security", []) for key in entry}
        self.assertIn("ChannelApiToken", security_schemes)
