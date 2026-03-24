from panther_upwind_helpers import (
    upwind_base_alert_context,
    upwind_format_initiators,
    upwind_format_mitre_attacks,
    upwind_is_known_severity,
    upwind_severity,
)

# Upwind API detections cover broken authentication/authorization, injection,
# mass assignment, token misuse, sensitive data exposure, and API abuse patterns.
API_KEYWORDS = ("api",)


def rule(event):
    category = event.get("category", "").lower()
    return upwind_is_known_severity(event) and any(kw in category for kw in API_KEYWORDS)


def title(event):
    return f"[Upwind API]: {event.get('title', '<NO TITLE>')}"


def severity(event):
    return upwind_severity(event)


def dedup(event):
    return f"{event.get('id', '<NO ID>')}_{event.get('severity', '<NO SEVERITY>')}"


def description(event):
    return event.get("description") or "DEFAULT"


def reference(event):
    return event.get("upwind_console_link") or "DEFAULT"


def alert_context(event):
    ctx = upwind_base_alert_context(event)
    ctx["initiators"] = upwind_format_initiators(event)
    ctx["mitre_attacks"] = upwind_format_mitre_attacks(event)
    return ctx
