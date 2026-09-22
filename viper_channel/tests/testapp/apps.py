from django.apps import AppConfig


class TestAppConfig(AppConfig):
    """Minimal reference host implementation for viper_channel's standalone test suite.

    Exists only to prove viper_channel has zero real dependency on
    medisao/acadia/mcai/public_api: it supplies the smallest possible
    Device/Organization/Advisory stand-ins that satisfy the settings seams
    (``VIPER_DEVICE_MODEL`` etc.) exercised through the real, portable
    viper_channel code. See viper_channel/README.md.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "viper_channel.tests.testapp"
    label = "testapp"
