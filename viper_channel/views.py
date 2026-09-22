"""ARPA-H/VIPER channel read API (public, versioned).

Machine-to-machine, pull-only, cursor + ``since`` pagination. Every read routes
through the visibility backend seam (``get_visibility_backend().channels_for()``
/ ``.advisories_for()``) plus the in-app choke point
(``Remediation.objects.channel_remediations``) so opt-in + medisao + PUBLISHED +
TLP:CLEAR/GREEN are enforced in exactly one place. See
docs/arpah-viper-integration.md §5.

The staff-only channel-token admin endpoints (mint/list/revoke a
``ChannelApiToken``) live in ``medisao/views.py`` instead of here: they
authenticate with medcrypt's own JWT stack, which this app has no business
depending on.
"""

import uuid

from django.http import FileResponse
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.generics import ListAPIView, ListCreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from viper_channel.auth import (
    ChannelBearerAuthentication,
    ChannelConsumerThrottle,
    IsValidChannelConsumer,
)
from viper_channel.backends import get_file_path_validator, get_visibility_backend
from viper_channel.models import (
    ChannelSubscription,
    CommentAuthorProvider,
    Remediation,
    RemediationCommentAuthor,
)
from viper_channel.pagination import ViperCursorPagination
from viper_channel.serializers import (
    ChannelAdvisorySerializer,
    ChannelRemediationCommentSerializer,
    ChannelRemediationSerializer,
    ChannelSerializer,
    ChannelSubscriptionSerializer,
    InquirySerializer,
)

SINCE_PARAM = OpenApiParameter(
    "since",
    str,
    description="Only rows updated strictly after this ISO-8601 timestamp.",
)


def _parse_since(request):
    """Parse ``?since=`` into a datetime, or ``None``. Raises 400 on garbage."""
    raw = request.query_params.get("since")
    if not raw:
        return None
    parsed = parse_datetime(raw)
    if parsed is None:
        raise ValidationError({"since": "Must be an ISO-8601 datetime, e.g. 2026-06-01T00:00:00Z."})
    return parsed


class _ChannelCursorPagination(ViperCursorPagination):
    ordering = "-last_modified"


class _ContentCursorPagination(ViperCursorPagination):
    ordering = "-updated_at"


class _CommentCursorPagination(ViperCursorPagination):
    # Comments are append-only — there is no edit endpoint — so creation time is
    # the stable sync axis, and `?since=` filters the same column the cursor
    # orders by (a cursor ordered on a different column than the filter is how
    # polling clients silently skip rows).
    ordering = "-created_at"


class _ChannelAuthMixin:
    """Shared auth/permission/throttle wiring for every channel endpoint —
    inheritable by ListAPIView, ListCreateAPIView, and APIView alike."""

    authentication_classes = [ChannelBearerAuthentication]
    permission_classes = [IsValidChannelConsumer]
    throttle_classes = [ChannelConsumerThrottle]


def _resolve_channel(request, channel_id):
    """The channel for ``channel_id`` if valid for this token, else 404.

    Same choke point as listing (``channels_for``) so an opted-out / archived /
    cross-tenant id can never be used to reach or mutate channel data.
    """
    device = get_visibility_backend().channels_for(request.auth).filter(pk=channel_id).first()
    if device is None:
        raise NotFound("Channel not found.")
    return device


class _ChannelBaseView(_ChannelAuthMixin, ListAPIView):
    """Base for channel list endpoints."""


@extend_schema_view(
    get=extend_schema(
        summary="List channels",
        description="List device channels visible to the calling consumer token.",
        parameters=[
            SINCE_PARAM,
            OpenApiParameter(
                "manufacturer_id",
                str,
                description="Filter to one manufacturer org UUID.",
            ),
        ],
        tags=["Channels"],
    )
)
class ChannelListView(_ChannelBaseView):
    serializer_class = ChannelSerializer
    pagination_class = _ChannelCursorPagination

    def get_queryset(self):
        qs = get_visibility_backend().channels_for(self.request.auth).select_related("workspace__organization")
        since = _parse_since(self.request)
        if since:
            qs = qs.filter(last_modified__gt=since)
        manufacturer_id = self.request.query_params.get("manufacturer_id")
        if manufacturer_id:
            # Coerce to UUID so a garbage value is a clean 400, not a 500 when
            # the ORM tries to cast it at query time.
            try:
                manufacturer_id = uuid.UUID(manufacturer_id)
            except (ValueError, TypeError):
                # `from None`: the caller sent a bad id, and the parse error behind
                # it is our internal detail, not something to chain into a 400.
                raise ValidationError({"manufacturer_id": "Must be a valid UUID."}) from None
            qs = qs.filter(workspace__organization_id=manufacturer_id)
        return qs.order_by("-last_modified")


class _ChannelScopedListView(_ChannelBaseView):
    """Base for reads scoped to a single ``channel_id`` in the URL."""

    pagination_class = _ContentCursorPagination

    def get_channel_device(self):
        return _resolve_channel(self.request, self.kwargs["channel_id"])


@extend_schema_view(
    get=extend_schema(
        summary="List channel advisories",
        description="Published TLP:CLEAR/GREEN advisories on a channel.",
        parameters=[SINCE_PARAM],
        tags=["Channels"],
    )
)
class ChannelAdvisoryListView(_ChannelScopedListView):
    serializer_class = ChannelAdvisorySerializer

    def get_queryset(self):
        device = self.get_channel_device()
        qs = get_visibility_backend().advisories_for(device, self.request.auth)
        since = _parse_since(self.request)
        if since:
            qs = qs.filter(updated_at__gt=since)
        return qs.order_by("-updated_at")


@extend_schema_view(
    get=extend_schema(
        summary="List channel remediations",
        description="Published TLP:CLEAR/GREEN remediations on a channel.",
        parameters=[SINCE_PARAM],
        tags=["Channels"],
    )
)
class ChannelRemediationListView(_ChannelScopedListView):
    serializer_class = ChannelRemediationSerializer

    def get_queryset(self):
        device = self.get_channel_device()
        qs = Remediation.objects.channel_remediations(device, self.request.auth).select_related(
            "device__workspace__organization"
        )
        since = _parse_since(self.request)
        if since:
            qs = qs.filter(updated_at__gt=since)
        return qs.order_by("-updated_at")


@extend_schema_view(
    put=extend_schema(
        summary="Subscribe to a channel",
        request=None,
        responses=ChannelSubscriptionSerializer,
        tags=["Channels"],
    ),
    delete=extend_schema(
        summary="Unsubscribe from a channel",
        request=None,
        responses=None,
        tags=["Channels"],
    ),
)
class ChannelSubscribeView(_ChannelAuthMixin, APIView):
    """PUT/DELETE a consumer's subscription to a channel (idempotent both ways).

    Under open discovery this is bookkeeping only — advisory/remediation access
    never requires a subscription — but the contract (§5) expects the endpoints.
    """

    def put(self, request, channel_id):
        device = _resolve_channel(request, channel_id)
        sub, created = ChannelSubscription.objects.get_or_create(consumer=request.auth, device=device)
        return Response(
            ChannelSubscriptionSerializer(sub).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request, channel_id):
        # Idempotent and self-scoped: only ever removes THIS consumer's own
        # subscription, so we don't re-gate on channel validity — a consumer
        # must be able to drop a subscription even after the channel opts out.
        ChannelSubscription.objects.filter(consumer=request.auth, device_id=channel_id).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


def _resolve_visible_remediation(request, remediation_id):
    """The remediation for ``remediation_id`` if it is published on a channel
    visible to this token, else 404 — routed through ``channel_remediations``."""
    remediation = Remediation.objects.select_related("device").filter(pk=remediation_id).first()
    if remediation is None:
        raise NotFound("Remediation not found.")
    visible = Remediation.objects.channel_remediations(remediation.device, request.auth).filter(pk=remediation.pk)
    if not visible.exists():
        raise NotFound("Remediation not found.")
    return remediation


@extend_schema_view(
    get=extend_schema(
        summary="List inquiries on a remediation",
        description="The calling consumer's own inquiries about a remediation.",
        parameters=[SINCE_PARAM],
        tags=["Channels"],
    ),
    post=extend_schema(summary="Raise an inquiry about a remediation", tags=["Channels"]),
)
class RemediationInquiryListCreateView(_ChannelAuthMixin, ListCreateAPIView):
    """GET/POST inquiries on a remediation — the one inbound write from VIPER.

    A consumer sees and creates only its OWN inquiries (scoped by token), so a
    future second consumer can never read VIPER's questions.
    """

    serializer_class = InquirySerializer
    pagination_class = _ContentCursorPagination

    def get_queryset(self):
        remediation = _resolve_visible_remediation(self.request, self.kwargs["remediation_id"])
        qs = remediation.inquiries.filter(consumer=self.request.auth)
        since = _parse_since(self.request)
        if since:
            qs = qs.filter(updated_at__gt=since)
        return qs.order_by("-updated_at")

    def perform_create(self, serializer):
        remediation = _resolve_visible_remediation(self.request, self.kwargs["remediation_id"])
        serializer.save(remediation=remediation, consumer=self.request.auth)


@extend_schema_view(
    get=extend_schema(
        summary="List comments on a remediation",
        description=(
            "Pseudonymous HDO comments on a remediation. Unlike inquiries, comments are a "
            "shared conversation: every consumer that can see the remediation sees every "
            "comment on it. Authors are protected by the pseudonym, not by restricted "
            "readership — two comments sharing a pseudonym on this remediation are the same "
            "person, and that same person's pseudonym on another remediation is uncorrelated."
        ),
        parameters=[SINCE_PARAM],
        tags=["Channels"],
    ),
    post=extend_schema(summary="Comment on a remediation as an HDO user", tags=["Channels"]),
)
class RemediationCommentListCreateView(_ChannelAuthMixin, ListCreateAPIView):
    """GET/POST pseudonymous comments on a remediation (docs/hdo-remediation-comments.md §4).

    The identity the consumer asserts (``author_provider`` +
    ``author_external_user_id``) is consumed here and stored on
    ``RemediationCommentAuthor``; it never appears in a response, including the
    201 the poster gets back.
    """

    serializer_class = ChannelRemediationCommentSerializer
    pagination_class = _CommentCursorPagination

    def get_queryset(self):
        from viper_channel.models import RemediationComment

        remediation = _resolve_visible_remediation(self.request, self.kwargs["remediation_id"])
        # select_related the author: the serialized `pseudonym` and
        # `remediation_id` both hang off it, so without this every row costs an
        # extra query on an endpoint VIPER polls.
        qs = RemediationComment.objects.channel_comments(remediation, self.request.auth).select_related("author")
        since = _parse_since(self.request)
        if since:
            qs = qs.filter(created_at__gt=since)
        return qs.order_by("-created_at")

    def perform_create(self, serializer):
        remediation = _resolve_visible_remediation(self.request, self.kwargs["remediation_id"])
        # Belt and braces with the serializer's single-choice ChoiceField: a
        # channel token must never be able to mint a MEDISAO_NATIVE identity,
        # because that provider is Medcrypt's own attestation that it
        # authenticated the human (§2.2). Only our session flow may set it.
        provider = serializer.validated_data.pop("author_provider")
        external_user_id = serializer.validated_data.pop("author_external_user_id")
        if provider != CommentAuthorProvider.VIPER:
            raise ValidationError({"author_provider": "A channel token may only assert 'viper'."})

        author = RemediationCommentAuthor.resolve(
            provider=CommentAuthorProvider.VIPER,
            external_user_id=external_user_id,
            remediation=remediation,
            # v1 GLOBAL tokens carry no hdo_org, so the realm is the consumer;
            # `resolve` promotes it to the org realm the moment v2 mints
            # HDO-scoped tokens. Either way the org is only recorded when known.
            org=self.request.auth.hdo_org,
            consumer=self.request.auth,
        )
        serializer.save(author=author)


@extend_schema_view(get=extend_schema(summary="Download a remediation artifact", tags=["Channels"]))
class ChannelRemediationFileDownloadView(_ChannelAuthMixin, APIView):
    """Stream a remediation artifact to VIPER.

    Routed through the same ``channel_remediations`` gate as the remediation
    itself, so a file is only downloadable while its remediation is published +
    TLP:CLEAR/GREEN on a channel the token can see. Always served as an
    ATTACHMENT with ``X-Content-Type-Options: nosniff`` — the file crosses the
    tenant boundary, so it must never render inline (stored-XSS guard).
    """

    def get(self, request, channel_id, remediation_id, file_id):
        remediation = _resolve_visible_remediation(request, remediation_id)
        if str(remediation.device_id) != str(channel_id):
            raise NotFound("File not found.")
        remediation_file = remediation.files.filter(pk=file_id).first()
        if remediation_file is None:
            raise NotFound("File not found.")

        validator = get_file_path_validator()
        path = validator(remediation_file.file_path) if validator else None
        if path is None:
            raise NotFound("File not found.")

        response = FileResponse(
            open(path, "rb"),
            as_attachment=True,
            filename=remediation_file.name,
            content_type=remediation_file.content_type or "application/octet-stream",
        )
        response["X-Content-Type-Options"] = "nosniff"
        return response
