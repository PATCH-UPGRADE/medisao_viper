"""Pseudonymous author identity for remediation comments.

Implements docs/hdo-remediation-comments.md §2.3:

    pseudonym = HMAC(realm_secret, provider ∥ external_user_id ∥ remediation_id)

Three properties the derivation exists to deliver, and why each input is there:

* **Pseudonymous on the wire** — a keyed HMAC, not a bare hash. A bare hash of
  ``user_id + remediation_id`` is brute-forceable by anyone who can enumerate an
  HDO's (small) user roster and try each until one matches the pseudonym shown on
  the channel. The secret closes that off.
* **Linkable within one remediation** — the derivation is deterministic and
  carries no nonce, so the same person commenting twice on the same remediation
  always produces the same pseudonym.
* **Unlinkable across remediations** — ``remediation_id`` is an input, so the
  same person's pseudonym on another remediation is uncorrelated without the
  secret.

``provider`` is part of the input because VIPER's user-id space and MedISAO's
native ``User.pk`` space can collide on the same literal value for two different
humans. ``realm`` (see :func:`realm_key_for_org` / :func:`realm_key_for_consumer`)
scopes the secret so one identity domain's linkage can be revoked without
touching any other's.
"""

import hashlib
import hmac
import secrets

REALM_ORG = "org"
REALM_CONSUMER = "consumer"

SECRET_BYTES = 32


def realm_key_for_org(org) -> str:
    """Realm key for an HDO org whose users Medcrypt authenticates itself."""
    return f"{REALM_ORG}:{getattr(org, 'pk', org)}"


def realm_key_for_consumer(token) -> str:
    """Realm key for a consumer application asserting identities it authenticated.

    DELIBERATE v1 fallback: the design (§2.3) scopes the secret per HDO *org*,
    but a v1 ``ChannelApiToken`` is ``GLOBAL`` and carries no ``hdo_org`` — VIPER
    does HDO-level authorization downstream and never tells us which hospital a
    commenter belongs to. So when the token has no org, the realm is the calling
    consumer instead. Rotation granularity then matches exactly what we actually
    know about the identity, and the moment v2 mints HDO-scoped tokens the realm
    becomes per-org with no schema change (see :func:`realm_key_for_token`).
    """
    return f"{REALM_CONSUMER}:{getattr(token, 'pk', token)}"


def realm_key_for_token(token) -> str:
    """The realm a channel-token-asserted identity belongs to.

    Per-HDO-org as soon as the token is HDO-scoped (v2), per-consumer while it is
    ``GLOBAL`` (v1). Pseudonyms do not survive a token's promotion from GLOBAL to
    HDO scope — that changes the realm, which is the point of the realm: it is
    the boundary the secret protects.
    """
    hdo_org_id = getattr(token, "hdo_org_id", None)
    if hdo_org_id is not None:
        return f"{REALM_ORG}:{hdo_org_id}"
    return realm_key_for_consumer(token)


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def _canonical_message(*, realm_key: str, provider: str, external_user_id: str, remediation_id) -> bytes:
    """Length-prefix every component before concatenating.

    Plain concatenation is ambiguous — ``("viper", "1", "23")`` and
    ``("viper", "12", "3")`` would hash identically and collapse two different
    people into one pseudonym. Length prefixes make the encoding injective.
    """
    parts = [realm_key, provider, str(external_user_id), str(remediation_id)]
    return "".join(f"{len(p)}:{p}" for p in parts).encode("utf-8")


def derive_pseudonym(
    *,
    secret: bytes,
    realm_key: str,
    provider: str,
    external_user_id: str,
    remediation_id,
) -> str:
    """The channel-facing pseudonym for one (person, remediation) pair."""
    message = _canonical_message(
        realm_key=realm_key,
        provider=provider,
        external_user_id=external_user_id,
        remediation_id=remediation_id,
    )
    return hmac.new(bytes(secret), message, hashlib.sha256).hexdigest()
