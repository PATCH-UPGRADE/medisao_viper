import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    """Fresh initial migration for a standalone install.

    Every FK onto a host model (device/organization/advisory) is resolved via
    ``settings.VIPER_DEVICE_MODEL`` / ``VIPER_ORGANIZATION_MODEL`` /
    ``VIPER_ADVISORY_MODEL`` — set these before running ``migrate`` for the
    first time. See README.md.
    """

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ChannelApiToken",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "consumer_name",
                    models.CharField(
                        help_text="Human label for the consumer app, e.g. 'VIPER'.",
                        max_length=120,
                    ),
                ),
                (
                    "token_hash",
                    models.CharField(
                        db_index=True, editable=False, max_length=64, unique=True
                    ),
                ),
                (
                    "token_prefix",
                    models.CharField(
                        editable=False,
                        help_text="First chars of the raw token — non-secret, for identification only.",
                        max_length=12,
                    ),
                ),
                (
                    "scope_type",
                    models.CharField(
                        choices=[
                            ("global", "Global (all channels)"),
                            ("hdo", "Scoped to one HDO (v2)"),
                        ],
                        default="global",
                        max_length=8,
                    ),
                ),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "hdo_org",
                    models.ForeignKey(
                        blank=True,
                        help_text="v2 only: the HDO this token is scoped to when scope_type=hdo.",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="channel_tokens",
                        to=settings.VIPER_ORGANIZATION_MODEL,
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="minted_channel_tokens",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="ChannelSubscription",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "consumer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="subscriptions",
                        to="viper_channel.channelapitoken",
                    ),
                ),
                (
                    "device",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="channel_subscriptions",
                        to=settings.VIPER_DEVICE_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="channelsubscription",
            constraint=models.UniqueConstraint(
                fields=("consumer", "device"),
                name="uq_channel_subscription_per_consumer",
            ),
        ),
        migrations.CreateModel(
            name="Remediation",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "version",
                    models.CharField(
                        blank=True,
                        help_text="Affected version (plain or VERS).",
                        max_length=128,
                        null=True,
                    ),
                ),
                (
                    "version_text",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                (
                    "tlp",
                    models.CharField(
                        choices=[
                            ("CLEAR", "TLP:CLEAR (Public)"),
                            ("GREEN", "TLP:GREEN (Community)"),
                            ("AMBER", "TLP:AMBER (Limited)"),
                            ("AMBER_STRICT", "TLP:AMBER+STRICT (Named recipients)"),
                            ("RED", "TLP:RED (Restricted)"),
                        ],
                        db_index=True,
                        default="CLEAR",
                        max_length=12,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[("draft", "Draft"), ("published", "Published")],
                        db_index=True,
                        default="draft",
                        help_text="Only PUBLISHED remediations are disseminated on channels.",
                        max_length=12,
                    ),
                ),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                (
                    "category",
                    models.CharField(
                        choices=[
                            ("vendor_fix", "Vendor fix"),
                            ("mitigation", "Mitigation"),
                            ("workaround", "Workaround"),
                            ("none_available", "None available"),
                            ("no_fix_planned", "No fix planned"),
                        ],
                        default="vendor_fix",
                        max_length=20,
                    ),
                ),
                (
                    "mechanism",
                    models.CharField(
                        choices=[
                            ("firmware_patch", "Firmware / software patch"),
                            ("network_segmentation", "Network segmentation"),
                            ("firewall_rule", "Firewall rule"),
                            ("access_control", "Access control change"),
                            ("monitoring_detection", "Monitoring / detection"),
                            ("other", "Other"),
                        ],
                        default="firmware_patch",
                        max_length=24,
                    ),
                ),
                (
                    "description",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Short summary of the remediation.",
                    ),
                ),
                (
                    "narrative",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Full remediation guidance / steps.",
                    ),
                ),
                (
                    "fixed_vulnerabilities",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="CVE-… / GHSA-… identifiers this remediation resolves.",
                    ),
                ),
                ("requires_downtime", models.BooleanField(default=False)),
                (
                    "estimated_downtime_seconds",
                    models.PositiveIntegerField(blank=True, null=True),
                ),
                ("restart_required", models.BooleanField(default=False)),
                ("disables_features", models.BooleanField(default=False)),
                ("workflow_impact", models.TextField(blank=True, default="")),
                ("clinical_impact_notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "device",
                    models.ForeignKey(
                        help_text="The channel (device) this remediation is disseminated on.",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="channel_remediations",
                        to=settings.VIPER_DEVICE_MODEL,
                    ),
                ),
                (
                    "advisory",
                    models.ForeignKey(
                        blank=True,
                        help_text="The advisory this remediation addresses, if any.",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="remediations",
                        to=settings.VIPER_ADVISORY_MODEL,
                    ),
                ),
                (
                    "author_org",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="authored_remediations",
                        to=settings.VIPER_ORGANIZATION_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-updated_at"],
            },
        ),
        migrations.AddIndex(
            model_name="remediation",
            index=models.Index(
                fields=["device", "status", "updated_at"],
                name="viper_chann_device__16d572_idx",
            ),
        ),
        migrations.CreateModel(
            name="RemediationFile",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                (
                    "file_path",
                    models.CharField(
                        help_text="EFS path from save_uploaded_file; not a public URL.",
                        max_length=1024,
                    ),
                ),
                (
                    "file_hash",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="SHA-256 of the file contents.",
                        max_length=64,
                    ),
                ),
                (
                    "content_type",
                    models.CharField(blank=True, default="", max_length=120),
                ),
                ("size_bytes", models.PositiveBigIntegerField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "remediation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="files",
                        to="viper_channel.remediation",
                    ),
                ),
            ],
            options={
                "ordering": ["created_at"],
            },
        ),
        migrations.CreateModel(
            name="Inquiry",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "body",
                    models.TextField(
                        help_text="The question text from the HDO/consumer."
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("open", "Open"),
                            ("answered", "Answered"),
                            ("closed", "Closed"),
                        ],
                        db_index=True,
                        default="open",
                        max_length=8,
                    ),
                ),
                (
                    "response",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="The MDM's answer (single-response, v1).",
                    ),
                ),
                ("responded_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "remediation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="inquiries",
                        to="viper_channel.remediation",
                    ),
                ),
                (
                    "consumer",
                    models.ForeignKey(
                        blank=True,
                        help_text="The consumer token that raised this inquiry (attribution).",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="inquiries",
                        to="viper_channel.channelapitoken",
                    ),
                ),
                (
                    "responded_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="answered_inquiries",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name_plural": "Inquiries",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="inquiry",
            index=models.Index(
                fields=["remediation", "-created_at"],
                name="viper_chann_remedia_47b87e_idx",
            ),
        ),
        migrations.CreateModel(
            name="PseudonymSecret",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "realm_key",
                    models.CharField(
                        editable=False,
                        help_text="Realm identifier, e.g. 'org:<uuid>' or 'consumer:<uuid>'.",
                        max_length=64,
                        unique=True,
                    ),
                ),
                (
                    "secret",
                    models.BinaryField(
                        editable=False, help_text="Random HMAC key. Never serialized."
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "org",
                    models.OneToOneField(
                        blank=True,
                        help_text="Set when the realm is an organization (org-scoped realms only).",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="pseudonym_secret",
                        to=settings.VIPER_ORGANIZATION_MODEL,
                    ),
                ),
                (
                    "consumer",
                    models.OneToOneField(
                        blank=True,
                        help_text="Set when the realm is a consumer application (v1 GLOBAL tokens).",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="pseudonym_secret",
                        to="viper_channel.channelapitoken",
                    ),
                ),
            ],
            options={},
        ),
        migrations.AddConstraint(
            model_name="pseudonymsecret",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("consumer__isnull", True), ("org__isnull", False)),
                    models.Q(("consumer__isnull", False), ("org__isnull", True)),
                    _connector="OR",
                ),
                name="ck_pseudonym_secret_exactly_one_scope",
            ),
        ),
        migrations.CreateModel(
            name="RemediationCommentAuthor",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "realm_key",
                    models.CharField(db_index=True, editable=False, max_length=64),
                ),
                (
                    "provider",
                    models.CharField(
                        choices=[
                            (
                                "viper",
                                "VIPER (asserted by the consumer, not authenticated by us)",
                            ),
                            (
                                "medisao_native",
                                "MedISAO native (authenticated by Medcrypt)",
                            ),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "external_user_id",
                    models.CharField(
                        help_text="VIPER's own per-user id, or str(User.pk) for native. Opaque to the channel.",
                        max_length=255,
                    ),
                ),
                (
                    "pseudonym",
                    models.CharField(
                        db_index=True,
                        editable=False,
                        help_text="HMAC per pseudonyms.derive_pseudonym; cached so reads never recompute it.",
                        max_length=64,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "consumer",
                    models.ForeignKey(
                        blank=True,
                        help_text="The consumer token that asserted this identity (VIPER-provider only).",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="remediation_comment_authors",
                        to="viper_channel.channelapitoken",
                    ),
                ),
                (
                    "org",
                    models.ForeignKey(
                        blank=True,
                        help_text="The commenting HDO, when known (native auth or a v2 HDO-scoped token).",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="remediation_comment_authors",
                        to=settings.VIPER_ORGANIZATION_MODEL,
                    ),
                ),
                (
                    "remediation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="comment_authors",
                        to="viper_channel.remediation",
                    ),
                ),
            ],
            options={},
        ),
        migrations.AddConstraint(
            model_name="remediationcommentauthor",
            constraint=models.UniqueConstraint(
                fields=("realm_key", "provider", "external_user_id", "remediation"),
                name="uq_remediation_comment_author_identity",
            ),
        ),
        migrations.CreateModel(
            name="RemediationComment",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("body", models.TextField(help_text="The comment text.")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "author",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="comments",
                        to="viper_channel.remediationcommentauthor",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="remediationcomment",
            index=models.Index(
                fields=["author", "-created_at"], name="viper_chann_author__48bab7_idx"
            ),
        ),
        migrations.CreateModel(
            name="RemediationCommentRevealLog",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "comment_id_snapshot",
                    models.UUIDField(
                        help_text="The requested comment id, kept if the comment is deleted."
                    ),
                ),
                (
                    "outcome",
                    models.CharField(
                        choices=[
                            (
                                "confirmed",
                                "Confirmed — the caller authored this comment",
                            ),
                            ("denied", "Denied — not the caller's comment"),
                            ("unattestable", "Unattestable — VIPER-provider comment"),
                        ],
                        db_index=True,
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "comment",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="reveal_logs",
                        to="viper_channel.remediationcomment",
                    ),
                ),
                (
                    "requested_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
