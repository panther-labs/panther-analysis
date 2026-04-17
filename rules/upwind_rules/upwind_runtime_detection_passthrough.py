from panther_upwind_helpers import (
    upwind_base_alert_context,
    upwind_commands_observed,
    upwind_format_mitre_attacks,
    upwind_is_known_severity,
    upwind_severity,
)

# Upwind runtime detections cover process execution, syscall anomalies,
# container escapes, and other host/container behavioral threats.
RUNTIME_KEYWORDS = ("runtime", "execution", "process", "container")

# Defer to higher-priority rules when their keywords also appear in the category
RUNTIME_EXCLUSIONS = ("api", "vulnerab", "network")


def rule(event):
    category = event.get("category", "").lower()
    return (
        upwind_is_known_severity(event)
        and any(kw in category for kw in RUNTIME_KEYWORDS)
        and not any(ex in category for ex in RUNTIME_EXCLUSIONS)
    )


def title(event):
    return f"[Upwind Runtime]: {event.get('title', '<NO TITLE>')}"


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
    ctx["commands_observed"] = upwind_commands_observed(event)
    ctx["mitre_attacks"] = upwind_format_mitre_attacks(event)
    return ctx
