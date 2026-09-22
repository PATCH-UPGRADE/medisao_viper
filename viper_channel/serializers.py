"""Serializers for the ARPA-H/VIPER channel API (public, versioned).

STABILITY GUARANTEE: fields are not removed within v1; new fields may be added.
Field names are the wire contract with VIPER (docs/arpah-viper-integration.md §5).
All serializers are read-only (except the two comment/inquiry write paths).

``ChannelAdvisorySerializer`` is a plain ``serializers.Serializer`` (not a
``ModelSerializer``) so this app never has to import the host's Advisory model —
it just reads attributes off whatever ``get_visibility_backend().advisories_for()``
hands back.
"""

from rest_framework import serializers
from rest_framework.reverse import reverse

from viper_channel.models import (
    ChannelApiToken,
    ChannelSubscription,
    CommentAuthorProvider,
    Inquiry,
    Remediation,
    RemediationComment,
    RemediationFile,
)


class ChannelRefSerializer(serializers.Serializer):
    """The ``{vendor, product}`` stub embedded in advisory/remediation payloads."""

    vendor = serializers.CharField(source="workspace.organization.name", read_only=True)
    product = serializers.CharField(source="device_name", read_only=True)


class ChannelSerializer(serializers.Serializer):
    """A device exposed as a channel: ``{id, vendor, product, updated_at}``.

    ``id`` is the device UUID — stable across product renames, which is why
    VIPER keys its aliases on it. ``updated_at`` is the device's last-modified
    time and drives the ``?since=`` sync.
    """

    id = serializers.UUIDField(read_only=True)
    vendor = serializers.CharField(source="workspace.organization.name", read_only=True)
    product = serializers.CharField(source="device_name", read_only=True)
    updated_at = serializers.DateTimeField(source="last_modified", read_only=True)


class ChannelAdvisorySerializer(serializers.Serializer):
    """A published channel advisory as VIPER sees it.

    Plain ``Serializer`` (not ``ModelSerializer``) — this app has no Advisory
    model of its own; it reads these attributes off whatever the host's
    visibility backend returns for ``advisories_for(device, token)``.
    """

    id = serializers.UUIDField(read_only=True)
    channel = ChannelRefSerializer(source="device", read_only=True)
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    version = serializers.CharField(read_only=True)
    version_text = serializers.CharField(read_only=True)
    tlp = serializers.CharField(read_only=True)
    linked_vulnerabilities = serializers.ListField(child=serializers.CharField(), read_only=True)
    source_type = serializers.CharField(read_only=True)
    url = serializers.CharField(read_only=True)
    published_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class ChannelRemediationFileSerializer(serializers.ModelSerializer):
    """A remediation artifact as VIPER sees it — metadata + an authenticated
    download URL. The bytes are served (attachment only) via that URL, never
    inline and never as a public path."""

    download_url = serializers.SerializerMethodField()

    class Meta:
        model = RemediationFile
        fields = [
            "id",
            "name",
            "content_type",
            "size_bytes",
            "file_hash",
            "download_url",
        ]
        read_only_fields = fields

    def get_download_url(self, obj) -> str:
        return reverse(
            "viper_channel:channel-remediation-file",
            kwargs={
                "channel_id": obj.remediation.device_id,
                "remediation_id": obj.remediation_id,
                "file_id": obj.pk,
            },
            request=self.context.get("request"),
        )


class ChannelRemediationSerializer(serializers.ModelSerializer):
    """A published channel remediation as VIPER sees it (CSAF-aligned)."""

    channel = ChannelRefSerializer(source="device", read_only=True)
    advisory_id = serializers.UUIDField(read_only=True)
    inquiries = serializers.IntegerField(source="inquiries.count", read_only=True)
    inquiries_url = serializers.SerializerMethodField()
    comments_url = serializers.SerializerMethodField()
    files = ChannelRemediationFileSerializer(many=True, read_only=True)

    class Meta:
        model = Remediation
        fields = [
            "id",
            "channel",
            "advisory_id",
            "version",
            "version_text",
            "tlp",
            "category",
            "mechanism",
            "description",
            "narrative",
            "fixed_vulnerabilities",
            # Clinical impact (what an HDO needs to plan the fix).
            "requires_downtime",
            "estimated_downtime_seconds",
            "restart_required",
            "disables_features",
            "workflow_impact",
            "clinical_impact_notes",
            "inquiries",
            "inquiries_url",
            "comments_url",
            "files",
            "published_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_inquiries_url(self, obj) -> str:
        return reverse(
            "viper_channel:remediation-inquiries",
            kwargs={"remediation_id": obj.pk},
            request=self.context.get("request"),
        )

    def get_comments_url(self, obj) -> str:
        # A link, deliberately not a count: `inquiries` above is a per-row
        # `.count()`, i.e. one query per remediation in the list. Copying that
        # shape onto comments would double an existing N+1 on a polled endpoint.
        return reverse(
            "viper_channel:remediation-comments",
            kwargs={"remediation_id": obj.pk},
            request=self.context.get("request"),
        )


class ChannelSubscriptionSerializer(serializers.ModelSerializer):
    """A consumer's subscription record (bookkeeping under open discovery)."""

    channel_id = serializers.UUIDField(source="device_id", read_only=True)

    class Meta:
        model = ChannelSubscription
        fields = ["id", "channel_id", "created_at"]
        read_only_fields = fields


class InquirySerializer(serializers.ModelSerializer):
    """An inquiry on a remediation. ``body`` is the only client-writable field;
    the MDM's ``response`` is read-only from the consumer's side."""

    remediation_id = serializers.UUIDField(read_only=True)
    # Cap the one inbound free-text write (the model field is an unbounded
    # TextField) so a consumer can't grow storage with a giant body.
    body = serializers.CharField(max_length=10000)

    class Meta:
        model = Inquiry
        fields = [
            "id",
            "remediation_id",
            "body",
            "status",
            "response",
            "responded_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "remediation_id",
            "status",
            "response",
            "responded_at",
            "created_at",
            "updated_at",
        ]


class ChannelRemediationCommentSerializer(serializers.ModelSerializer):
    """A pseudonymous comment on a remediation, as every channel consumer sees it.

    PRIVACY CONTRACT (docs/hdo-remediation-comments.md §3.3, §4.2): the read
    shape is ``pseudonym`` and nothing else about the author. ``provider`` and
    ``external_user_id`` live on ``RemediationCommentAuthor`` and MUST never be
    added here — the reveal endpoint is the only way either leaves that table.

    Two comments sharing a ``pseudonym`` on this remediation are the same person;
    the same person's pseudonym on a different remediation looks unrelated.

    Write side: ``author_provider`` + ``author_external_user_id`` are write-only
    inputs consumed by the view to resolve the author row. The response is the
    read shape — a consumer gets back exactly what everyone else sees, not the
    raw identity it just asserted.
    """

    remediation_id = serializers.UUIDField(read_only=True)
    pseudonym = serializers.CharField(read_only=True)
    author_provider = serializers.ChoiceField(
        choices=[(CommentAuthorProvider.VIPER, CommentAuthorProvider.VIPER.label)],
        write_only=True,
        help_text=(
            "Must be 'viper'. A channel token can never assert 'medisao_native' on someone's "
            "behalf — that provider means Medcrypt authenticated the person itself."
        ),
    )
    author_external_user_id = serializers.CharField(
        max_length=255,
        write_only=True,
        allow_blank=False,
        trim_whitespace=True,
        help_text=(
            "The consumer's own stable per-user id. Stability is the one contract requirement "
            "on the caller: rotate it and the person's pseudonym changes, breaking the "
            "linkable-within-a-remediation guarantee."
        ),
    )
    # Cap the free-text write (the model field is an unbounded TextField) so a
    # consumer can't grow storage with a giant body — same cap as Inquiry.
    body = serializers.CharField(max_length=10000, allow_blank=False, trim_whitespace=True)

    class Meta:
        model = RemediationComment
        fields = [
            "id",
            "remediation_id",
            "pseudonym",
            "body",
            "created_at",
            "author_provider",
            "author_external_user_id",
        ]
        read_only_fields = ["id", "remediation_id", "pseudonym", "created_at"]


class ChannelApiTokenSerializer(serializers.ModelSerializer):
    """Metadata view of a channel consumer credential (e.g. VIPER).

    Read-only and secret-free by construction: the raw bearer token is stored
    only as a hash, so it can NEVER be serialized here. ``token_prefix`` is a
    non-secret display handle for correlating a row with a live credential.
    The raw token is surfaced exactly once, by the mint endpoint, outside this
    serializer.
    """

    created_by_email = serializers.SerializerMethodField()

    class Meta:
        model = ChannelApiToken
        fields = [
            "id",
            "consumer_name",
            "token_prefix",
            "scope_type",
            "is_active",
            "last_seen_at",
            "created_at",
            "created_by_email",
        ]
        read_only_fields = fields

    def get_created_by_email(self, obj) -> str | None:
        return obj.created_by.email if obj.created_by else None
