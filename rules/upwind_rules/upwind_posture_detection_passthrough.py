SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Upwind posture detections cover cloud misconfigurations, exposed secrets,
# configuration drift, and CSPM policy violations.
# Note: "config" intentionally excluded — too broad and covered by "misconfigur".
POSTURE_KEYWORDS = ("posture", "cspm", "misconfigur")

# Defer to higher-priority rules when their keywords also appear in the category
POSTURE_EXCLUSIONS = ("api", "vulnerab", "network")


def rule(event):
    category = event.get("category", "").lower()
    return (
        event.get("severity", "").upper() in SEVERITY_MAP
        and any(kw in category for kw in POSTURE_KEYWORDS)
        and not any(ex in category for ex in POSTURE_EXCLUSIONS)
    )


def title(event):
    return f"[Upwind Posture]: {event.get('title', '<NO TITLE>')}"


def severity(event):
    return SEVERITY_MAP.get(event.get("severity", "").upper(), "DEFAULT")


def dedup(event):
    return f"{event.get('id', '<NO ID>')}_{event.get('severity', '<NO SEVERITY>')}"


def description(event):
    return event.get("description") or "DEFAULT"


def reference(event):
    return event.get("upwind_console_link") or "DEFAULT"


def alert_context(event):
    resource = event.get("resource", {})
    policies = [t.get("policy_name") for t in event.get("triggers", []) if t.get("policy_name")]
    return {
        "detection_id": event.get("id"),
        "category": event.get("category"),
        "type": event.get("type"),
        "status": event.get("status"),
        "occurrence_count": event.get("occurrence_count"),
        "resource": {
            "name": resource.get("name"),
            "type": resource.get("type"),
            "region": resource.get("region"),
            "cloud_provider": resource.get("cloud_provider"),
            "cloud_account_id": resource.get("cloud_account_id"),
            "cloud_account_name": resource.get("cloud_account_name"),
            "risk_categories": resource.get("risk_categories", []),
        },
        "triggered_policies": policies,
    }
