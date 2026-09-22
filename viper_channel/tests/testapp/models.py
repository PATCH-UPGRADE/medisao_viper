"""Minimal reference host models for viper_channel's standalone test suite.

These stand in for ``acadia.Device`` / ``acadia.Organization`` / a channel
``Advisory`` model — exactly the shape ``viper_channel`` needs through its
settings seams (``VIPER_DEVICE_MODEL`` / ``VIPER_ORGANIZATION_MODEL`` /
``VIPER_ADVISORY_MODEL``), nothing more.

Deliberately DOES include a ``Workspace`` indirection (``Device.workspace``)
even though it is medcrypt-specific bookkeeping the stub host doesn't
conceptually need — omitting it would break the real, portable
``viper_channel`` code paths that hardcode the field name: the wire contract
(``ChannelSerializer.vendor`` = ``source="workspace.organization.name"``) and
the query shape (``ChannelListView.get_queryset()`` calls
``.select_related("workspace__organization")`` and filters
``workspace__organization_id=...``). ``select_related`` only works over real
DB relations, so a stub Device needs the same field name, not just an
attribute that resolves via a Python property. Any host wiring in
``VIPER_DEVICE_MODEL`` inherits this same requirement.

Deliberately DOES NOT include the org-licensing check
(``feature_flags__medisao``) that ``acadia.models.DeviceChannelQuerySet.channels_for``
applies — that's medcrypt-specific policy layered on top of the portable
contract, not something a reference host needs to demonstrate.
"""

import uuid

from django.db import models

from viper_channel.enums import CHANNEL_VISIBLE_TLP, PublishStatus


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class Workspace(models.Model):
    """Thin indirection layer — see module docstring for why this exists."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="workspaces")
    name = models.CharField(max_length=255, blank=True, default="")

    def __str__(self):
        return self.name or str(self.id)


class DeviceQuerySet(models.QuerySet):
    """Mirrors ``acadia.models.DeviceChannelQuerySet.channels_for`` minus the
    medcrypt-specific org-licensing gate (see module docstring)."""

    def channels_for(self, token) -> "DeviceQuerySet":
        return self.filter(is_publicly_discoverable=True, is_archived=False)


class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device_name = models.CharField(max_length=255)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name="devices")
    is_publicly_discoverable = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)
    last_modified = models.DateTimeField(auto_now=True)

    objects = DeviceQuerySet.as_manager()

    def __str__(self):
        return self.device_name


class AdvisoryQuerySet(models.QuerySet):
    """Mirrors ``medisao.models.AdvisoryQuerySet.channel_advisories``."""

    def channel_advisories(self, device, token) -> "AdvisoryQuerySet":
        if device is None:
            return self.none()
        visible_devices = Device.objects.channels_for(token)
        return self.filter(
            device=device,
            device__in=visible_devices,
            status=PublishStatus.PUBLISHED,
            tlp__in=CHANNEL_VISIBLE_TLP,
        )


class Advisory(models.Model):
    """Minimal stand-in for the host's Advisory model.

    ``viper_channel`` never imports this directly — it goes through
    ``get_visibility_backend().advisories_for(device, token)``
    (see ``viper_channel/tests/testapp/backend.py``). Field set matches exactly
    what ``ChannelAdvisorySerializer`` (a plain ``serializers.Serializer``)
    reads off whatever the backend hands back.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(
        Device,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="advisories",
    )
    author_org = models.ForeignKey(
        Organization,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="authored_advisories",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    version = models.CharField(max_length=128, blank=True, default="")
    version_text = models.CharField(max_length=255, blank=True, default="")
    tlp = models.CharField(max_length=12, default="CLEAR")
    status = models.CharField(max_length=12, default=PublishStatus.DRAFT)
    linked_vulnerabilities = models.JSONField(default=list, blank=True)
    source_type = models.CharField(max_length=32, blank=True, default="")
    url = models.CharField(max_length=1024, blank=True, default="")
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = AdvisoryQuerySet.as_manager()

    def save(self, *args, **kwargs):
        from django.utils import timezone

        if self.status == PublishStatus.PUBLISHED and self.published_at is None:
            self.published_at = timezone.now()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
