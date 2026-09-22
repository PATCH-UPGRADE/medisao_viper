# viper_channel

The ARPA-H / VIPER channel API: machine-to-machine bearer-token endpoints that
let an external consumer (VIPER) discover opted-in device "channels" and pull
published, TLP:CLEAR/GREEN advisories, remediations, remediation files, and
pseudonymous HDO comments/inquiries off them.

## Zero-dependency design

This app has no dependency on any other application-specific code — it never
imports a host's device/organization/advisory models directly. Everywhere it
needs a concrete host model or host behavior, it reads a Django settings seam
instead and resolves it lazily via `django.utils.module_loading.import_string`
(see `viper_channel/backends.py`):

- `VIPER_DEVICE_MODEL` — the "channel" model (a device/product), as an
  `"app_label.Model"` string (same convention as Django's own
  `AUTH_USER_MODEL`).
- `VIPER_ORGANIZATION_MODEL` — the manufacturer/HDO model.
- `VIPER_ADVISORY_MODEL` — the host's advisory model (used only for the FK
  target on `Remediation.advisory`; `viper_channel` never queries Advisory
  directly).
- `VIPER_VISIBILITY_BACKEND` — dotted path to a class implementing
  `channels_for(token)` / `advisories_for(device, token)`. The single choke
  point every view resolves channel/advisory visibility through — write your
  own to wrap your real device/advisory querysets (opt-in, publish status,
  TLP, whatever your license/feature model requires).
- `VIPER_LLM_PROVIDER` — optional draft-assist callable (used by
  `viper_channel.authoring.draft_assist` to suggest advisory copy from a
  disclosure), or `None` to disable draft-assist entirely.
- `VIPER_FILE_PATH_VALIDATOR` — callable that turns a stored `file_path` into
  a safe on-disk path (or `None` if invalid), or `None` to disable remediation
  file downloads.

`viper_channel/tests/testapp/` is a from-scratch, minimal reference host
(`Device` / `Organization` / `Advisory` stub models, a `StubVisibilityBackend`,
its own `urls.py`) that demonstrates exactly what a host application needs to
provide — read `viper_channel/tests/testapp/models.py` and `backend.py` as the
worked example for wiring this app into your own project.

## Installing into a Django project

1. Add `"viper_channel"` to `INSTALLED_APPS`.
2. Set the six `VIPER_*` settings above in your project settings.
3. `python manage.py migrate` — `viper_channel/migrations/0001_initial.py` is a
   normal, fresh initial migration; it creates its own tables (FKs resolve to
   whatever `VIPER_DEVICE_MODEL` etc. point at when you run `migrate`).
4. Mount `viper_channel.urls` wherever you want the API to live, e.g.
   `path("api/v1/", include("viper_channel.urls"))`. It declares
   `app_name = "viper_channel"`, so internal `reverse()` calls stay correct
   under any mount point.
5. `python manage.py mint_channel_token <consumer-name>` mints the first
   bearer token for a consumer (e.g. VIPER itself).

## Test suite

**Run against the bundled reference stub host** (proves the app works with
nothing but the settings seams — no external models required):

```bash
DJANGO_SETTINGS_MODULE=viper_channel.tests.testapp.standalone_settings \
  python -m pytest viper_channel/ --no-migrations
```

(`--no-migrations` uses pytest-django's single-pass schema sync instead of
replaying migrations — the stub `testapp` host has no migrations of its own,
since it exists only to demonstrate the model shape, not to be migrated in
production.)

`test_pseudonyms.py` has no host dependency at all. Every other test module
that needs `Device`/`Organization`/`Advisory` fixtures guards itself with:

```python
from django.apps import apps

if not apps.is_installed("viper_channel.tests.testapp"):
    import pytest

    pytest.skip(
        "requires DJANGO_SETTINGS_MODULE=viper_channel.tests.testapp.standalone_settings",
        allow_module_level=True,
    )
```

so if you embed this app in a larger project and point `VIPER_DEVICE_MODEL`
etc. at your own models, these modules collect as a clean skip under your
project's own test settings (where `viper_channel.tests.testapp` isn't
installed) instead of failing — your own project should have its own
equivalent coverage against your real models (see
`viper_channel/tests/testapp/backend.py`'s `StubVisibilityBackend` for the
shape a real implementation follows).
