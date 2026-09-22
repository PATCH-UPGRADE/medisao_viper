"""Reference implementations of the ``viper_channel`` settings seams, bound to
the stub ``testapp`` models. Mirrors ``medisao/viper_integration.py`` — the
real host's equivalent binding — but with zero medcrypt-specific policy."""

from pathlib import Path


class StubVisibilityBackend:
    """Bound to ``VIPER_VISIBILITY_BACKEND`` under the standalone test settings."""

    def channels_for(self, token):
        from viper_channel.tests.testapp.models import Device

        return Device.objects.channels_for(token)

    def advisories_for(self, device, token):
        from viper_channel.tests.testapp.models import Advisory

        return Advisory.objects.channel_advisories(device, token)


def stub_file_path_validator(file_path: str) -> str | None:
    """Trivial stand-in for ``medisao.viper_integration.validate_remediation_file_path``.

    Just confirms the path exists on disk — no medcrypt-specific EFS/tenant
    path-prefix checks, since those are host policy, not part of the portable
    contract this app needs to demonstrate.
    """
    if not file_path:
        return None
    path = Path(file_path)
    return path if path.is_file() else None
