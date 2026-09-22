"""Standalone Django settings for viper_channel's own test suite.

A from-scratch, minimal Django project settings module — only
``viper_channel`` itself plus the reference stub host app under
``viper_channel/tests/testapp/`` are installed. This is what an adopter's own
project settings need to provide (via ``VIPER_DEVICE_MODEL`` etc.) to run
this app; the stub host demonstrates the minimum shape required. See
``viper_channel/README.md`` for the run commands.

Note for anyone embedding ``viper_channel`` inside a larger Django project
that ALSO wants to run this test module: ``viper_channel.models`` resolves
``settings.VIPER_DEVICE_MODEL`` etc. at class-definition time (module import
time), and Django only defines each model class once per process — so this
settings module cannot be loaded in the same process as your own project's
settings if they point the seams at different concrete models. Run it as its
own, separate ``pytest`` invocation:
``DJANGO_SETTINGS_MODULE=viper_channel.tests.testapp.standalone_settings pytest viper_channel/``.
"""

SECRET_KEY = "standalone-test-secret-key-not-for-production"

DEBUG = False
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "drf_spectacular",
    "viper_channel",
    "viper_channel.tests.testapp",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

AUTH_USER_MODEL = "auth.User"

ROOT_URLCONF = "viper_channel.tests.testapp.urls"

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "VIPER Channel API (standalone)",
    "VERSION": "1.0.0",
}

# ── viper_channel settings seams, bound to the stub testapp models ──────────
VIPER_DEVICE_MODEL = "testapp.Device"
VIPER_ORGANIZATION_MODEL = "testapp.Organization"
VIPER_ADVISORY_MODEL = "testapp.Advisory"
VIPER_VISIBILITY_BACKEND = "viper_channel.tests.testapp.backend.StubVisibilityBackend"
VIPER_LLM_PROVIDER = None
VIPER_FILE_PATH_VALIDATOR = "viper_channel.tests.testapp.backend.stub_file_path_validator"

USE_X_FORWARDED_HOST = False
