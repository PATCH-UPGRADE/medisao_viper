"""Resolvers for the settings-configurable seams this app depends on.

``viper_channel`` is decoupled from medcrypt-specific models/behavior: it never
imports ``acadia`` or ``medisao`` for anything. Instead it reads these small
hooks from Django settings and resolves them lazily via ``import_string``, so
the host application (medisao) can bind them to its real models/behavior
without this app needing to know medisao exists.

See ``medisao/viper_integration.py`` for the concrete implementations wired in
via ``VIPER_VISIBILITY_BACKEND`` / ``VIPER_LLM_PROVIDER`` /
``VIPER_FILE_PATH_VALIDATOR`` in ``srv/settings.py``.
"""

from functools import lru_cache

from django.conf import settings
from django.utils.module_loading import import_string


@lru_cache(maxsize=1)
def get_visibility_backend():
    """The object providing ``channels_for(token)`` / ``advisories_for(device, token)``.

    The SINGLE choke point ``viper_channel`` views use to resolve which channels
    (devices) and advisories a consumer token may see — never filtered inline.

    Cached: ``VIPER_VISIBILITY_BACKEND`` is read once at process start and never
    changes without a restart, so re-resolving it per call is pure waste on a
    machine-to-machine endpoint VIPER polls continuously.
    """
    return import_string(settings.VIPER_VISIBILITY_BACKEND)()


@lru_cache(maxsize=1)
def get_llm_provider():
    """The draft-assist LLM callable, or ``None`` if draft-assist is disabled."""
    path = getattr(settings, "VIPER_LLM_PROVIDER", None)
    return import_string(path) if path else None


@lru_cache(maxsize=1)
def get_file_path_validator():
    """The callable that turns a stored ``file_path`` into a safe on-disk path
    (or ``None`` if invalid), or ``None`` if no validator is configured."""
    path = getattr(settings, "VIPER_FILE_PATH_VALIDATOR", None)
    return import_string(path) if path else None
