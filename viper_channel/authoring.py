"""MDM-side remediation publish/unpublish + LLM draft-assist for the
ARPA-H/VIPER channels (see docs/arpah-viper-integration.md §6).

Advisory-only authoring (``graduate_disclosure_to_advisory``,
``create_sbom_advisory``, ``publish_advisory``, ``unpublish_advisory``) stays in
``medisao.channel_authoring`` — ``Advisory`` does not move to this app.

``draft_assist`` is duck-typed over its argument (reads ``.device_id``,
``.device.device_name``, ``.name``, ``.version``, ``.linked_vulnerabilities``,
``.description``) so it works unmodified for either an ``Advisory`` or a
``Remediation``-shaped object, without this app importing either model.
"""

import logging

from pydantic import BaseModel, Field

from viper_channel.backends import get_llm_provider
from viper_channel.models import PublishStatus

logger = logging.getLogger(__name__)


def publish_remediation(remediation):
    """DRAFT -> PUBLISHED. ``save()`` stamps ``published_at`` once."""
    remediation.status = PublishStatus.PUBLISHED
    remediation.save()
    return remediation


def unpublish_remediation(remediation):
    """PUBLISHED -> DRAFT (pull it back off the channel)."""
    remediation.status = PublishStatus.DRAFT
    remediation.published_at = None
    remediation.save()
    return remediation


# ── LLM draft-assist ─────────────────────────────────────────────────────────


class AdvisoryDraftSuggestion(BaseModel):
    """Suggested prose for a channel advisory. Draft-assist only — the MDM edits
    and approves before anything is published."""

    name: str = Field(description="A concise advisory title.")
    description: str = Field(description="A one-paragraph summary for an HDO audience.")
    narrative: str = Field(description="A fuller plain-language explanation of impact and next steps.")


ADVISORY_DRAFT_SYSTEM_PROMPT = (
    "You help a medical-device manufacturer draft a security advisory for the "
    "hospitals that operate their device. Write clearly and factually for a "
    "clinical/biomed audience. Do NOT invent CVEs, versions, or fixes that are "
    "not in the provided context. The manufacturer will review and edit your "
    "draft before it is published."
)


def _advisory_context(advisory) -> str:
    parts = [
        f"Product: {advisory.device.device_name}" if advisory.device_id else "",
        f"Working title: {advisory.name}",
        f"Affected version: {advisory.version}" if advisory.version else "",
        f"Linked vulnerabilities: {', '.join(advisory.linked_vulnerabilities)}"
        if advisory.linked_vulnerabilities
        else "",
        f"Existing description: {advisory.description}" if advisory.description else "",
    ]
    return "\n".join(p for p in parts if p)


def draft_assist(advisory, *, invoke=None) -> dict:
    """Return an LLM-suggested ``{name, description, narrative}`` for ``advisory``.

    Draft-assist only: does NOT persist or publish anything — the caller shows
    the suggestion to the MDM, who edits and saves it themselves. ``invoke`` is
    injectable so callers/tests can substitute the LLM; when not supplied it
    defaults to ``settings.VIPER_LLM_PROVIDER`` (or a no-op if unset/disabled).
    """
    invoke = invoke or get_llm_provider()
    if invoke is None:
        return AdvisoryDraftSuggestion(name=advisory.name, description="", narrative="").model_dump()
    suggestion = invoke(_advisory_context(advisory))
    return suggestion.model_dump()
