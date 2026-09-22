"""ARPA-H / VIPER channel API models (see docs/arpah-viper-integration.md).

This app is decoupled from medcrypt-specific models via settings-configurable
seams: FKs onto the device/organization/advisory models use
``settings.VIPER_DEVICE_MODEL`` / ``settings.VIPER_ORGANIZATION_MODEL`` /
``settings.VIPER_ADVISORY_MODEL`` instead of hardcoded ``"acadia.Device"`` etc,
so this app can eventually be lifted out of this repo without a rewrite.
``medisao.viper_integration`` binds those seams to medcrypt's real models.

``TLP`` / ``PublishStatus`` / ``CHANNEL_VISIBLE_TLP`` live in
``viper_channel.enums``, not here or in ``medisao`` — the host's ``Advisory``
model (which does not move) also needs them, and defining them on this
(portable) app rather than the host means this app never has to import
``medisao`` to get its own vocabulary. ``medisao.models`` imports and
re-exports them under the same names so existing callers are unaffected.
"""

import hashlib
import secrets
import uuid

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from viper_channel.enums import CHANNEL_VISIBLE_TLP, TLP, PublishStatus


class ChannelApiToken(models.Model):
    """Machine-to-machine bearer credential for a channel *consumer* application.

    In v1 the only consumer is VIPER; the token identifies *who is calling* (for
    audit, inquiry attribution, throttling) but does NOT narrow which channels
    are visible — VIPER performs its own HDO-level authorization downstream.

    Stored as a SHA-256 hash; the raw token is shown exactly once at mint time
    (see :meth:`issue`). ``token_prefix`` is a non-secret display handle for
    admin/log correlation.

    v2 forward-compat seam: ``scope_type``/``hdo_org``. v1 only mints ``GLOBAL``
    tokens; honoring ``HDO`` scope later is a narrowing inside
    ``get_visibility_backend().channels_for()``/``.advisories_for()`` (see
    ``viper_channel/backends.py`` and ``medisao/viper_integration.py``), which
    already receive the token — no schema or endpoint change. See §4.6–4.7.
    """

    class Scope(models.TextChoices):
        GLOBAL = "global", "Global (all channels)"
        HDO = "hdo", "Scoped to one HDO (v2)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    consumer_name = models.CharField(max_length=120, help_text="Human label for the consumer app, e.g. 'VIPER'.")
    token_hash = models.CharField(max_length=64, unique=True, db_index=True, editable=False)
    token_prefix = models.CharField(
        max_length=12,
        editable=False,
        help_text="First chars of the raw token — non-secret, for identification only.",
    )
    scope_type = models.CharField(max_length=8, choices=Scope.choices, default=Scope.GLOBAL)
    hdo_org = models.ForeignKey(
        settings.VIPER_ORGANIZATION_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="channel_tokens",
        help_text="v2 only: the HDO this token is scoped to when scope_type=hdo.",
    )
    is_active = models.BooleanField(default=True, db_index=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="minted_channel_tokens",
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.consumer_name} ({self.token_prefix}…)"

    # ── DRF principal duck-typing ────────────────────────────────────────────
    # ChannelBearerAuthentication returns this token as request.user/request.auth,
    # so it must quack like an authenticated principal (it IS one — a machine
    # consumer). These make IsAuthenticated-style checks and DRF internals behave.
    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    @staticmethod
    def _hash(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @classmethod
    def issue(cls, *, consumer_name: str, created_by=None, **kwargs) -> tuple["ChannelApiToken", str]:
        """Mint a new token. Returns ``(instance, raw_token)``; the raw token is
        the ONLY time the secret is available — it is never stored in the clear."""
        raw_token = secrets.token_urlsafe(32)
        instance = cls.objects.create(
            consumer_name=consumer_name,
            token_hash=cls._hash(raw_token),
            token_prefix=raw_token[:8],
            created_by=created_by,
            **kwargs,
        )
        return instance, raw_token

    @classmethod
    def authenticate(cls, raw_token: str) -> "ChannelApiToken | None":
        """Resolve a raw bearer token to an active consumer, or ``None``.

        Lookup is by hash equality (the raw token carries ample entropy, so a
        DB hash match is not timing-sensitive). Bumps ``last_seen_at``.
        """
        if not raw_token:
            return None
        try:
            token = cls.objects.get(token_hash=cls._hash(raw_token), is_active=True)
        except cls.DoesNotExist:
            return None
        # Best-effort activity stamp; never block auth on the write.
        cls.objects.filter(pk=token.pk).update(last_seen_at=timezone.now())
        return token


class RemediationCategory(models.TextChoices):
    """CSAF 2.0 remediation categories."""

    VENDOR_FIX = "vendor_fix", "Vendor fix"
    MITIGATION = "mitigation", "Mitigation"
    WORKAROUND = "workaround", "Workaround"
    NONE_AVAILABLE = "none_available", "None available"
    NO_FIX_PLANNED = "no_fix_planned", "No fix planned"


class RemediationMechanism(models.TextChoices):
    """How a remediation is applied (drives clinical-impact expectations)."""

    FIRMWARE_PATCH = "firmware_patch", "Firmware / software patch"
    NETWORK_SEGMENTATION = "network_segmentation", "Network segmentation"
    FIREWALL_RULE = "firewall_rule", "Firewall rule"
    ACCESS_CONTROL = "access_control", "Access control change"
    MONITORING_DETECTION = "monitoring_detection", "Monitoring / detection"
    OTHER = "other", "Other"


class RemediationQuerySet(models.QuerySet):
    """Remediation queryset carrying the channel visibility rule.

    NOTE: the host-scoped ``commentable_by(user)`` method that used to live here
    moved to ``medisao.viper_integration.commentable_remediations_for`` — it
    reaches into ``HdoConnection``, a medcrypt-specific host model, so it cannot
    live in this decoupled app.
    """

    def channel_remediations(self, device, token) -> "RemediationQuerySet":
        """Remediations disseminated on ``device``'s channel to ``token``.

        SINGLE visibility choke point for channel remediation reads (sibling of
        ``AdvisoryQuerySet.channel_advisories`` in ``medisao.models`` — same
        two-gate contract: channel validity via ``channels_for`` + PUBLISHED +
        TLP:CLEAR/GREEN, falsy ``device`` yields nothing).
        """
        if device is None:
            return self.none()
        from viper_channel.backends import get_visibility_backend

        visible_devices = get_visibility_backend().channels_for(token)
        return self.filter(
            device=device,
            device__in=visible_devices,
            status=PublishStatus.PUBLISHED,
            tlp__in=CHANNEL_VISIBLE_TLP,
        )


class Remediation(models.Model):
    """A CSAF-aligned remediation an MDM publishes on a device channel.

    Mirrors the ``medisao_patch`` reference model: CSAF category + application
    mechanism + clinical-impact fields (downtime, workflow disruption) that HDOs
    need to plan a fix. Only PUBLISHED + TLP:CLEAR/GREEN rows reach VIPER.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(
        settings.VIPER_DEVICE_MODEL,
        on_delete=models.CASCADE,
        related_name="channel_remediations",
        help_text="The channel (device) this remediation is disseminated on.",
    )
    advisory = models.ForeignKey(
        settings.VIPER_ADVISORY_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="remediations",
        help_text="The advisory this remediation addresses, if any.",
    )
    author_org = models.ForeignKey(
        settings.VIPER_ORGANIZATION_MODEL,
        on_delete=models.CASCADE,
        related_name="authored_remediations",
    )

    version = models.CharField(
        max_length=128,
        blank=True,
        null=True,
        help_text="Affected version (plain or VERS).",
    )
    version_text = models.CharField(max_length=255, blank=True, null=True)
    tlp = models.CharField(max_length=12, choices=TLP.choices, default=TLP.CLEAR, db_index=True)
    status = models.CharField(
        max_length=12,
        choices=PublishStatus.choices,
        default=PublishStatus.DRAFT,
        db_index=True,
        help_text="Only PUBLISHED remediations are disseminated on channels.",
    )
    published_at = models.DateTimeField(null=True, blank=True)

    category = models.CharField(
        max_length=20,
        choices=RemediationCategory.choices,
        default=RemediationCategory.VENDOR_FIX,
    )
    mechanism = models.CharField(
        max_length=24,
        choices=RemediationMechanism.choices,
        default=RemediationMechanism.FIRMWARE_PATCH,
    )

    description = models.TextField(blank=True, default="", help_text="Short summary of the remediation.")
    narrative = models.TextField(blank=True, default="", help_text="Full remediation guidance / steps.")
    fixed_vulnerabilities = models.JSONField(
        default=list,
        blank=True,
        help_text="CVE-… / GHSA-… identifiers this remediation resolves.",
    )

    # ── Clinical impact (what an HDO needs to plan the fix) ──────────────────
    requires_downtime = models.BooleanField(default=False)
    estimated_downtime_seconds = models.PositiveIntegerField(null=True, blank=True)
    restart_required = models.BooleanField(default=False)
    disables_features = models.BooleanField(default=False)
    workflow_impact = models.TextField(blank=True, default="")
    clinical_impact_notes = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = RemediationQuerySet.as_manager()

    class Meta:
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["device", "status", "updated_at"]),
        ]

    def save(self, *args, **kwargs):
        if self.status == PublishStatus.PUBLISHED and self.published_at is None:
            self.published_at = timezone.now()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"[{self.get_tlp_display()}] {self.get_category_display()} for {self.device_id}"


class RemediationFile(models.Model):
    """A file/artifact attached to a remediation (patch notes, firmware, etc.).

    Stored on EFS (``file_path`` from ``save_uploaded_file``); never a public
    URL — served through an authenticated channel endpoint. Minimal in v1.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    remediation = models.ForeignKey(Remediation, on_delete=models.CASCADE, related_name="files")
    name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=1024, help_text="EFS path from save_uploaded_file; not a public URL.")
    file_hash = models.CharField(max_length=64, blank=True, default="", help_text="SHA-256 of the file contents.")
    content_type = models.CharField(max_length=120, blank=True, default="")
    size_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.name} ({self.remediation_id})"


class InquiryStatus(models.TextChoices):
    OPEN = "open", "Open"
    ANSWERED = "answered", "Answered"
    CLOSED = "closed", "Closed"


class Inquiry(models.Model):
    """An HDO→MDM question about a remediation — the one inbound write from VIPER.

    v1 uses a single ``response`` field (not a thread); a threaded model can be
    added later without breaking this shape.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    remediation = models.ForeignKey(Remediation, on_delete=models.CASCADE, related_name="inquiries")
    consumer = models.ForeignKey(
        ChannelApiToken,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="inquiries",
        help_text="The consumer token that raised this inquiry (attribution).",
    )
    body = models.TextField(help_text="The question text from the HDO/consumer.")
    status = models.CharField(
        max_length=8,
        choices=InquiryStatus.choices,
        default=InquiryStatus.OPEN,
        db_index=True,
    )
    response = models.TextField(blank=True, default="", help_text="The MDM's answer (single-response, v1).")
    responded_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="answered_inquiries",
    )
    responded_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Inquiries"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["remediation", "-created_at"]),
        ]

    def __str__(self):
        return f"Inquiry on {self.remediation_id} ({self.status})"


class ChannelSubscription(models.Model):
    """A consumer's bookkeeping record of a channel it tracks.

    Under open discovery, advisory/remediation access does NOT require a
    subscription — this just records VIPER's "which channels do I follow" so the
    PUT/DELETE /subscribe contract has somewhere to land.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    consumer = models.ForeignKey(ChannelApiToken, on_delete=models.CASCADE, related_name="subscriptions")
    device = models.ForeignKey(
        settings.VIPER_DEVICE_MODEL,
        on_delete=models.CASCADE,
        related_name="channel_subscriptions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["consumer", "device"],
                name="uq_channel_subscription_per_consumer",
            ),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.consumer_id} -> {self.device_id}"


# ═════════════════════════════════════════════════════════════════════════════
# HDO remediation comments (see docs/hdo-remediation-comments.md)
# ═════════════════════════════════════════════════════════════════════════════


class PseudonymSecret(models.Model):
    """The HMAC key for one pseudonym *realm* (see ``viper_channel/pseudonyms.py``).

    A realm is the identity domain a commenter belongs to: an HDO organization
    when Medcrypt knows which one (native auth, or a v2 HDO-scoped channel
    token), otherwise the consumer application that asserted the identity. One
    secret per realm — not one global key — so a realm's pseudonym linkage can be
    revoked by deleting its row without touching anyone else's.

    The secret is never exposed through any API or serializer; it exists only to
    key the HMAC. Deleting a row is effectively "rotate": every pseudonym this
    realm ever published goes dead (they will not re-derive), which is why
    rotation is not offered as an endpoint. See §6 open question 1.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    realm_key = models.CharField(
        max_length=64,
        unique=True,
        editable=False,
        help_text="Realm identifier, e.g. 'org:<uuid>' or 'consumer:<uuid>'.",
    )
    org = models.OneToOneField(
        settings.VIPER_ORGANIZATION_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="pseudonym_secret",
        help_text="Set when the realm is an organization (org-scoped realms only).",
    )
    consumer = models.OneToOneField(
        ChannelApiToken,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="pseudonym_secret",
        help_text="Set when the realm is a consumer application (v1 GLOBAL tokens).",
    )
    secret = models.BinaryField(editable=False, help_text="Random HMAC key. Never serialized.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(org__isnull=False, consumer__isnull=True)
                | models.Q(org__isnull=True, consumer__isnull=False),
                name="ck_pseudonym_secret_exactly_one_scope",
            ),
        ]

    def __str__(self):
        return f"PseudonymSecret({self.realm_key})"

    @classmethod
    def for_realm(cls, *, realm_key: str, org=None, consumer=None) -> "PseudonymSecret":
        """Get-or-create this realm's secret, generating one on first use.

        Concurrency: two simultaneous first comments in the same realm race here.
        ``realm_key`` is unique, so the loser's INSERT fails and it re-reads the
        winner's row — both end up with the SAME secret, which is what makes the
        pseudonym reproducible.
        """
        from django.db import IntegrityError, transaction

        from viper_channel import pseudonyms

        existing = cls.objects.filter(realm_key=realm_key).first()
        if existing is not None:
            return existing
        try:
            with transaction.atomic():
                return cls.objects.create(
                    realm_key=realm_key,
                    org=org,
                    consumer=consumer,
                    secret=pseudonyms.new_secret(),
                )
        except IntegrityError:
            return cls.objects.get(realm_key=realm_key)


class CommentAuthorProvider(models.TextChoices):
    """Who authenticated the human behind a comment — and therefore who can
    later attest to their identity (§2.4). Medcrypt can attest only to
    ``MEDISAO_NATIVE``; ``VIPER`` identities are VIPER's to confirm, out of band.
    """

    VIPER = "viper", "VIPER (asserted by the consumer, not authenticated by us)"
    MEDISAO_NATIVE = "medisao_native", "MedISAO native (authenticated by Medcrypt)"


class RemediationCommentAuthor(models.Model):
    """The ONLY place a comment's raw identity lives.

    Never joined into a channel-facing query or serializer: the wire sees
    ``pseudonym`` and nothing else. ``provider`` and ``external_user_id`` leave
    this table only through the self-reveal endpoint (§4.3).

    One row per (realm, provider, external_user_id, remediation) — that
    uniqueness is what makes the same person's comments on one remediation share
    an identity, and it is enforced in the database, not just in the derivation.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    realm_key = models.CharField(max_length=64, editable=False, db_index=True)
    org = models.ForeignKey(
        settings.VIPER_ORGANIZATION_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="remediation_comment_authors",
        help_text="The commenting HDO, when known (native auth or a v2 HDO-scoped token).",
    )
    consumer = models.ForeignKey(
        ChannelApiToken,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="remediation_comment_authors",
        help_text="The consumer token that asserted this identity (VIPER-provider only).",
    )
    provider = models.CharField(max_length=16, choices=CommentAuthorProvider.choices)
    external_user_id = models.CharField(
        max_length=255,
        help_text="VIPER's own per-user id, or str(User.pk) for native. Opaque to the channel.",
    )
    remediation = models.ForeignKey(Remediation, on_delete=models.CASCADE, related_name="comment_authors")
    pseudonym = models.CharField(
        max_length=64,
        db_index=True,
        editable=False,
        help_text="HMAC per pseudonyms.derive_pseudonym; cached so reads never recompute it.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["realm_key", "provider", "external_user_id", "remediation"],
                name="uq_remediation_comment_author_identity",
            ),
        ]

    def __str__(self):
        return f"{self.pseudonym[:12]}… on {self.remediation_id}"

    @classmethod
    def resolve(
        cls,
        *,
        provider: str,
        external_user_id: str,
        remediation,
        org=None,
        consumer=None,
    ):
        """The author row for this identity on this remediation, creating it once.

        The pseudonym is derived here and cached on the row; every later comment
        by the same person on the same remediation reuses it rather than
        re-deriving (and rather than trusting the derivation to stay stable).
        """
        from django.db import IntegrityError, transaction

        from viper_channel import pseudonyms

        if org is not None:
            realm_key = pseudonyms.realm_key_for_org(org)
            secret_org, secret_consumer = org, None
        else:
            realm_key = pseudonyms.realm_key_for_token(consumer)
            # A v2 HDO-scoped token names an org realm; the secret must then be
            # owned by that org, not by the token, so a second token for the same
            # hospital derives the same pseudonyms.
            if getattr(consumer, "hdo_org_id", None) is not None:
                secret_org, secret_consumer = consumer.hdo_org, None
            else:
                secret_org, secret_consumer = None, consumer

        existing = cls.objects.filter(
            realm_key=realm_key,
            provider=provider,
            external_user_id=external_user_id,
            remediation=remediation,
        ).first()
        if existing is not None:
            return existing

        secret = PseudonymSecret.for_realm(realm_key=realm_key, org=secret_org, consumer=secret_consumer)
        pseudonym = pseudonyms.derive_pseudonym(
            secret=secret.secret,
            realm_key=realm_key,
            provider=provider,
            external_user_id=external_user_id,
            remediation_id=remediation.pk,
        )
        try:
            with transaction.atomic():
                return cls.objects.create(
                    realm_key=realm_key,
                    org=org,
                    consumer=consumer,
                    provider=provider,
                    external_user_id=external_user_id,
                    remediation=remediation,
                    pseudonym=pseudonym,
                )
        except IntegrityError:
            # Concurrent first comment by the same person: the unique constraint
            # decided who wins; take the winner's row so both comments share a
            # pseudonym rather than one 500ing.
            return cls.objects.get(
                realm_key=realm_key,
                provider=provider,
                external_user_id=external_user_id,
                remediation=remediation,
            )


class RemediationCommentQuerySet(models.QuerySet):
    """Comment queryset carrying the channel visibility rule."""

    def channel_comments(self, remediation, token) -> "RemediationCommentQuerySet":
        """Comments on ``remediation`` readable by ``token``.

        SINGLE visibility choke point for comment reads. Comments inherit the
        remediation's gate exactly — if the remediation is not currently
        published on a channel this token can see, neither are its comments.

        DELIBERATE difference from ``Inquiry``: inquiries are scoped to the
        consumer that raised them, comments are not. A comment thread is a shared
        conversation on the channel — the pseudonym is what protects the author,
        not restricted readership (§4.2).
        """
        if remediation is None:
            return self.none()
        visible = Remediation.objects.channel_remediations(remediation.device, token).filter(pk=remediation.pk)
        if not visible.exists():
            return self.none()
        return self.filter(author__remediation=remediation)


class RemediationComment(models.Model):
    """An HDO's pseudonymous comment on a remediation.

    A strict generalization of :class:`Inquiry`: an inquiry attributes to the
    calling token (the consumer application as a whole), a comment attributes to
    the individual human behind it — without identifying them to the channel.

    No ``device`` FK: the device is reached via ``author.remediation.device``,
    matching how ``Inquiry`` already derives its device context. That also keeps
    this model off ``Device``'s reverse-relation list, where every new relation
    owes bulk_trends an extraction decision.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    author = models.ForeignKey(RemediationCommentAuthor, on_delete=models.CASCADE, related_name="comments")
    body = models.TextField(help_text="The comment text.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = RemediationCommentQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["author", "-created_at"]),
        ]

    def __str__(self):
        return f"Comment by {self.author.pseudonym[:12]}… on {self.author.remediation_id}"

    @property
    def remediation_id(self):
        return self.author.remediation_id

    @property
    def pseudonym(self) -> str:
        return self.author.pseudonym


class RemediationCommentRevealLog(models.Model):
    """Audit row for every self-reveal attempt, allowed or refused (§4.3).

    A reveal is Medcrypt attesting to an identity it previously promised to keep
    off the wire; that attestation is exactly the kind of act that has to leave a
    trace whether or not it succeeded.
    """

    class Outcome(models.TextChoices):
        CONFIRMED = "confirmed", "Confirmed — the caller authored this comment"
        DENIED = "denied", "Denied — not the caller's comment"
        UNATTESTABLE = "unattestable", "Unattestable — VIPER-provider comment"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    comment = models.ForeignKey(
        RemediationComment,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reveal_logs",
    )
    comment_id_snapshot = models.UUIDField(help_text="The requested comment id, kept if the comment is deleted.")
    requested_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    outcome = models.CharField(max_length=16, choices=Outcome.choices, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"reveal({self.comment_id_snapshot}) -> {self.outcome}"
