from django.contrib import admin, messages

from viper_channel.models import (
    ChannelApiToken,
    ChannelSubscription,
    Inquiry,
    PseudonymSecret,
    Remediation,
    RemediationComment,
    RemediationCommentAuthor,
    RemediationCommentRevealLog,
    RemediationFile,
)


class RemediationFileInline(admin.TabularInline):
    model = RemediationFile
    extra = 0
    readonly_fields = ["created_at"]


@admin.register(Remediation)
class RemediationAdmin(admin.ModelAdmin):
    list_display = [
        "__str__",
        "device",
        "tlp",
        "status",
        "category",
        "mechanism",
        "updated_at",
    ]
    list_filter = ["tlp", "status", "category", "mechanism", "updated_at"]
    search_fields = ["description", "narrative"]
    autocomplete_fields = ["device", "advisory"]
    readonly_fields = ["created_at", "updated_at", "published_at"]
    inlines = [RemediationFileInline]


@admin.register(Inquiry)
class InquiryAdmin(admin.ModelAdmin):
    list_display = ["__str__", "remediation", "consumer", "status", "created_at"]
    list_filter = ["status", "created_at"]
    search_fields = ["body", "response"]
    readonly_fields = ["created_at", "updated_at", "responded_at"]


@admin.register(ChannelApiToken)
class ChannelApiTokenAdmin(admin.ModelAdmin):
    list_display = [
        "consumer_name",
        "token_prefix",
        "scope_type",
        "is_active",
        "last_seen_at",
        "created_at",
    ]
    list_filter = ["scope_type", "is_active"]
    search_fields = ["consumer_name", "token_prefix"]
    # token_hash/prefix are derived at mint time (via ChannelApiToken.issue); never hand-editable.
    readonly_fields = [
        "token_hash",
        "token_prefix",
        "last_seen_at",
        "created_at",
        "created_by",
    ]

    def get_fields(self, request, obj=None):
        # On "Add", only ask for what the mint needs; the hash/prefix are generated.
        if obj is None:
            return ["consumer_name", "scope_type", "hdo_org", "is_active"]
        return [
            "consumer_name",
            "token_prefix",
            "scope_type",
            "hdo_org",
            "is_active",
            "last_seen_at",
            "created_at",
        ]

    def save_model(self, request, obj, form, change):
        # Creating a token via the admin must go through issue() so the hash is
        # set and the raw bearer is generated. We can't reuse the unsaved `obj`
        # (it has no token_hash), so mint a fresh row and surface the raw token
        # once via a message — it is never stored in the clear or shown again.
        if change:
            super().save_model(request, obj, form, change)
            return
        token, raw_token = ChannelApiToken.issue(
            consumer_name=obj.consumer_name,
            created_by=request.user,
            scope_type=obj.scope_type,
            hdo_org=obj.hdo_org,
            is_active=obj.is_active,
        )
        # Point the admin at the real saved row (so the post-save redirect works).
        obj.pk = token.pk
        obj.token_hash = token.token_hash
        obj.token_prefix = token.token_prefix
        messages.warning(
            request,
            f"Channel token for '{token.consumer_name}' minted. Copy the bearer token now — "
            f"it is shown only once and cannot be recovered: {raw_token}",
        )


@admin.register(ChannelSubscription)
class ChannelSubscriptionAdmin(admin.ModelAdmin):
    list_display = ["consumer", "device", "created_at"]
    search_fields = ["consumer__consumer_name"]
    autocomplete_fields = ["device"]
    readonly_fields = ["created_at"]


# ── HDO remediation comments (docs/hdo-remediation-comments.md) ──────────────
# Admin is read-only on this whole family. These rows are the identity ledger
# behind a pseudonymity promise: an editable `pseudonym` would let a staff member
# silently re-attribute a comment, and an editable `external_user_id` would break
# the reveal attestation. Nothing here is meant to be hand-fixed.


@admin.register(RemediationComment)
class RemediationCommentAdmin(admin.ModelAdmin):
    list_display = ["__str__", "created_at"]
    list_filter = ["created_at"]
    search_fields = ["body"]
    readonly_fields = ["id", "author", "body", "created_at", "updated_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(RemediationCommentAuthor)
class RemediationCommentAuthorAdmin(admin.ModelAdmin):
    """The raw-identity table. Listed WITHOUT `external_user_id` on purpose —
    a staff list view is not a reveal endpoint."""

    list_display = [
        "pseudonym",
        "provider",
        "org",
        "consumer",
        "remediation",
        "created_at",
    ]
    list_filter = ["provider", "created_at"]
    search_fields = ["pseudonym"]
    readonly_fields = [f.name for f in RemediationCommentAuthor._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(RemediationCommentRevealLog)
class RemediationCommentRevealLogAdmin(admin.ModelAdmin):
    list_display = ["comment_id_snapshot", "outcome", "requested_by", "created_at"]
    list_filter = ["outcome", "created_at"]
    readonly_fields = [f.name for f in RemediationCommentRevealLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        # An audit trail you can delete from the admin is not an audit trail.
        return False


@admin.register(PseudonymSecret)
class PseudonymSecretAdmin(admin.ModelAdmin):
    """Realm secrets. `secret` is deliberately absent from every field list —
    it is the one value that must never be readable through a UI."""

    list_display = ["realm_key", "org", "consumer", "created_at"]
    search_fields = ["realm_key"]
    fields = ["realm_key", "org", "consumer", "created_at"]
    readonly_fields = ["realm_key", "org", "consumer", "created_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
