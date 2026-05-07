from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    if event.get("type") != "claude_artifact_sharing_updated":
        return False
    audience = event.get("audience")
    if audience is None:
        return False
    # In production, audience is a list of dicts like [{"type": "public"}].
    # The test framework may serialize nested objects differently, so we
    # check both structured access and string representation.
    if isinstance(audience, list):
        for entry in audience:
            if isinstance(entry, dict) and entry.get("type") == "public":
                return True
    # Fallback for test framework compatibility
    audience_str = str(audience)
    return ": 'public'" in audience_str or ': "public"' in audience_str


def title(event):
    actor_email = event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")
    artifact_id = event.get("claude_artifact_id", "<UNKNOWN_ARTIFACT>")
    return f"Anthropic: Artifact [{artifact_id}] shared publicly by [{actor_email}]"


def dedup(event):
    return event.deep_get("actor", "email_address", default="<UNKNOWN_EMAIL_ADDRESS>")


def alert_context(event):
    return anthropic_alert_context(event)
