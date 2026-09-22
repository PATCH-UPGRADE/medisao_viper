"""Cursor pagination for the VIPER channel API.

Stock DRF config (opaque cursor, stable iteration under a changing dataset) —
deliberately not imported from ``public_api.pagination``: this app must not
depend on another medcrypt-specific app to be independently installable.
"""

from rest_framework.pagination import CursorPagination


class ViperCursorPagination(CursorPagination):
    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 100
