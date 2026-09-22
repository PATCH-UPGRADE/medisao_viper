"""ARPA-H/VIPER channel URL patterns.

Mounted at the same URL prefix the ``public_api`` v1 channel paths previously
occupied (see ``public_api/v1/urls.py``), so the resolved paths
(``/api/public/v1/channels``, etc.) are byte-identical to before the move.
"""

from django.urls import path

from viper_channel.views import (
    ChannelAdvisoryListView,
    ChannelListView,
    ChannelRemediationFileDownloadView,
    ChannelRemediationListView,
    ChannelSubscribeView,
    RemediationCommentListCreateView,
    RemediationInquiryListCreateView,
)

app_name = "viper_channel"

urlpatterns = [
    path("channels", ChannelListView.as_view(), name="channel-list"),
    path(
        "channels/<uuid:channel_id>/advisories",
        ChannelAdvisoryListView.as_view(),
        name="channel-advisories",
    ),
    path(
        "channels/<uuid:channel_id>/remediations",
        ChannelRemediationListView.as_view(),
        name="channel-remediations",
    ),
    path(
        "channels/<uuid:channel_id>/remediations/<uuid:remediation_id>/files/<uuid:file_id>",
        ChannelRemediationFileDownloadView.as_view(),
        name="channel-remediation-file",
    ),
    path(
        "channels/<uuid:channel_id>/subscribe",
        ChannelSubscribeView.as_view(),
        name="channel-subscribe",
    ),
    path(
        "remediations/<uuid:remediation_id>/inquiries",
        RemediationInquiryListCreateView.as_view(),
        name="remediation-inquiries",
    ),
    path(
        "remediations/<uuid:remediation_id>/comments",
        RemediationCommentListCreateView.as_view(),
        name="remediation-comments",
    ),
]
