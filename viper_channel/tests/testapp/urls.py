"""ROOT_URLCONF for the standalone viper_channel test settings.

Mirrors the real mount point (``/api/public/v1/...``) so the standalone schema
test exercises the same resolved paths as production.
"""

from django.urls import include, path

urlpatterns = [
    path("api/public/v1/", include("viper_channel.urls")),
]
