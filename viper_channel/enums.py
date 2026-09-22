"""Vocabulary shared between ``viper_channel`` and the host's advisory model.

Traffic Light Protocol markings and the draft/published lifecycle gate are not
VIPER-specific concepts, but ``viper_channel.models.Remediation`` and the
host's ``Advisory`` model (which stays behind, see docs/arpah-viper-integration.md
§4) both need the same values for a consistent contract. Defined here — the
portable app — rather than on the host, so ``viper_channel`` never has to
import the host to get its own vocabulary; the host imports (and re-exports)
these instead. See ``medisao/models.py``, which does exactly that.
"""

from django.db import models


class TLP(models.TextChoices):
    """Traffic Light Protocol 2.0 markings for advisories (org-scoped sharing).

    * CLEAR        — public; the only tier visible without authentication.
    * GREEN        — the medisao community (any member).
    * AMBER        — author org + involved orgs (involvement not yet modelled, so
                     on an *authored* advisory this is effectively author-only).
    * AMBER+STRICT — author org + orgs it has explicitly allowlisted (``allowed_orgs``).
    * RED          — author org only.
    """

    CLEAR = "CLEAR", "TLP:CLEAR (Public)"
    GREEN = "GREEN", "TLP:GREEN (Community)"
    AMBER = "AMBER", "TLP:AMBER (Limited)"
    AMBER_STRICT = "AMBER_STRICT", "TLP:AMBER+STRICT (Named recipients)"
    RED = "RED", "TLP:RED (Restricted)"


class PublishStatus(models.TextChoices):
    """Lifecycle gate shared by channel-disseminated content (advisories,
    remediations). Only ``PUBLISHED`` rows are ever exposed to VIPER; ``DRAFT``
    is the MDM's private editing state."""

    DRAFT = "draft", "Draft"
    PUBLISHED = "published", "Published"


# TLP tiers that a channel ever exposes externally. The whole external surface
# is gated to these two — everything else stays internal regardless of publish
# state. Kept as a module constant so the gate is defined in exactly one place.
CHANNEL_VISIBLE_TLP = (TLP.CLEAR, TLP.GREEN)
