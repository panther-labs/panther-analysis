from panther_upwind_helpers import (
    upwind_base_alert_context,
    upwind_is_known_severity,
    upwind_severity,
    upwind_triggered_policies,
)

# Upwind posture detections cover cloud misconfigurations, exposed secrets,
# configuration drift, and CSPM policy violations.
# Note: "config" intentionally excluded — too broad and covered by "misconfigur".
POSTURE_KEYWORDS = ("posture", "cspm", "misconfigur")

# Defer to higher-priority rules when their keywords also appear in the category
POSTURE_EXCLUSIONS = ("api", "vulnerab", "network")


def rule(event):
    category = event.get("category", "").lower()
    return (
        upwind_is_known_severity(event)
        and any(kw in category for kw in POSTURE_KEYWORDS)
        and not any(ex in category for ex in POSTURE_EXCLUSIONS)
    )


def title(event):
    return f"[Upwind Posture]: {event.get('title', '<NO TITLE>')}"


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
    ctx["triggered_policies"] = upwind_triggered_policies(event)
    return ctx
