from panther_proofpoint_helpers import proofpoint_alert_context


def get_active_threat_count(event):
    # Count the number of active threats in the event using list comprehension
    return len([t for t in event.get("threatsInfoMap", []) if t.get("threatStatus") == "active"])


def rule(event):
    # Must have at least 2 active threats
    return get_active_threat_count(event) >= 2


def severity(event):
    active_count = get_active_threat_count(event)

    if active_count >= 5:
        return "CRITICAL"
    if active_count >= 3:
        return "HIGH"
    if active_count >= 2:
        return "MEDIUM"
    return "DEFAULT"


def title(event):
    sender = event.get("sender", "<UNKNOWN_SENDER>")
    active_count = get_active_threat_count(event)
    return f"Proofpoint: Multiple Threats Detected ({active_count}) - Email from {sender}"


def alert_context(event):
    # Use the common helper
    context = proofpoint_alert_context(event)

    # Filter to only active threats
    all_threats = context["threats"]
    active_threats = [t for t in all_threats if t.get("threatStatus") == "active"]
    threat_types = set(t.get("threatType") for t in active_threats if t.get("threatType"))
    classifications = set(
        t.get("classification") for t in active_threats if t.get("classification")
    )

    # Extend with multiple threat-specific fields
    context.update(
        {
            "threatCount": len(active_threats),
            "threatTypes": list(threat_types),
            "classifications": list(classifications),
            "threats": active_threats,
        }
    )
    return context
