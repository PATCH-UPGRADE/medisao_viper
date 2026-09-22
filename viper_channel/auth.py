"""Authentication / authorization / throttling for the ARPA-H/VIPER channel API.

These endpoints are consumed machine-to-machine by VIPER (see
docs/arpah-viper-integration.md §5), NOT by logged-in users, so they use a
dedicated bearer credential (:class:`viper_channel.models.ChannelApiToken`)
instead of the JWT/session stack. The authenticated *principal* is the token
itself.
"""

from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.throttling import UserRateThrottle

from viper_channel.models import ChannelApiToken


class ChannelBearerAuthentication(BaseAuthentication):
    """Validate ``Authorization: Bearer <token>`` against ``ChannelApiToken``.

    Returns ``(token, token)`` so both ``request.user`` and ``request.auth`` are
    the consumer token — the visibility choke points take it directly. Returns
    ``None`` (defer) when there is no bearer header; combined with
    ``authenticate_header`` returning "Bearer", a missing credential surfaces as a
    401 (NotAuthenticated) from the permission layer. A malformed or
    invalid/inactive token raises ``AuthenticationFailed`` (also 401).
    """

    keyword = "Bearer"

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None
        if len(auth) != 2:
            raise AuthenticationFailed("Invalid bearer authorization header.")
        try:
            raw_token = auth[1].decode()
        except UnicodeError:
            # `from None`: an auth failure must not carry decoder internals out to
            # an unauthenticated caller.
            raise AuthenticationFailed("Invalid bearer token encoding.") from None

        token = ChannelApiToken.authenticate(raw_token)
        if token is None:
            raise AuthenticationFailed("Invalid or inactive channel token.")
        return (token, token)

    def authenticate_header(self, request):
        return self.keyword


class ChannelBearerScheme(OpenApiAuthenticationExtension):
    """Document the channel bearer credential in the published OpenAPI schema.

    Auto-registered on import (this module is imported via the channel views), so
    the VIPER-facing docs show a ``bearer`` security scheme instead of dropping
    the authenticator with a warning.
    """

    target_class = "viper_channel.auth.ChannelBearerAuthentication"
    name = "ChannelApiToken"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "description": "VIPER channel API token (a viper_channel ChannelApiToken), minted by a MedISAO admin.",
        }


class IsValidChannelConsumer(BasePermission):
    """Allow only requests carrying a valid ``ChannelApiToken`` (via the auth above)."""

    def has_permission(self, request, view):
        return isinstance(getattr(request, "auth", None), ChannelApiToken)


class ChannelConsumerThrottle(UserRateThrottle):
    """Per-consumer rate limit, keyed on the token.

    ``ChannelBearerAuthentication`` sets ``request.user`` to the token itself,
    and ``ChannelApiToken.is_authenticated`` is always ``True``, so the stock
    ``UserRateThrottle`` cache key (``request.user.pk``) is already exactly
    "per consumer token" — no need to hand-roll ``get_cache_key``.
    """

    scope = "channel_consumer"
    rate = "6000/hour"  # set directly (like the other public_api throttles)
