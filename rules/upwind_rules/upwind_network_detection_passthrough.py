from panther_upwind_helpers import (
    upwind_base_alert_context,
    upwind_format_mitre_attacks,
    upwind_is_known_severity,
    upwind_severity,
)

# Upwind network detections cover port scans, DoS activity, DNS anomalies,
# DNS-over-HTTPS abuse, and other anomalous network behaviors.
NETWORK_KEYWORDS = ("network",)

# Defer to higher-priority rules when their keywords also appear in the category
NETWORK_EXCLUSIONS = ("api", "vulnerab")


def rule(event):
    category = event.get("category", "").lower()
    return (
        upwind_is_known_severity(event)
        and any(kw in category for kw in NETWORK_KEYWORDS)
        and not any(ex in category for ex in NETWORK_EXCLUSIONS)
    )


def title(event):
    return f"[Upwind Network]: {event.get('title', '<NO TITLE>')}"


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
    ctx["mitre_attacks"] = upwind_format_mitre_attacks(event)
    return ctx
