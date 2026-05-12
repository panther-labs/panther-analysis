from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    if event.get("type") != "claude_artifact_sharing_updated":
        return False
    audience = event.get("audience")
    if audience is None:
        return False
    # Panther's event wrapper intercepts .get("type") and ["type"] on nested
    # objects, returning the parent event's type. String matching on the
    # serialized audience is the only reliable approach in the test framework.
    # In production, audience entries only have a "type" key, so matching
    # "'public'" or '"public"' is equivalent to checking entry.type == "public".
    audience_str = str(audience)
    return "'public'" in audience_str or '"public"' in audience_str


def title(event):
    actor_email = anthropic_actor_id(event)
    artifact_id = event.get("claude_artifact_id", "<UNKNOWN_ARTIFACT>")
    return f"Anthropic: Artifact [{artifact_id}] shared publicly by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
