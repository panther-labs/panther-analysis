SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Upwind API detections cover broken authentication/authorization, injection,
# mass assignment, token misuse, sensitive data exposure, and API abuse patterns.
API_KEYWORDS = ("api",)


def rule(event):
    category = event.get("category", "").lower()
    return event.get("severity", "").upper() in SEVERITY_MAP and any(
        kw in category for kw in API_KEYWORDS
    )


def title(event):
    return f"[Upwind API]: {event.get('title', '<NO TITLE>')}"


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
    mitre = [
        {
            "tactic": m.get("tactic_name"),
            "technique_id": m.get("technique_id"),
            "technique": m.get("technique_name"),
        }
        for m in event.get("mitre_attacks", [])
    ]
    # Surface initiator info from trigger events when available
    initiators = []
    for trigger in event.get("triggers", []):
        for evt in trigger.get("events", []):
            if initiator := evt.get("initiator"):
                initiators.append(
                    {
                        "name": initiator.get("name"),
                        "type": initiator.get("type"),
                        "arn": initiator.get("arn"),
                        "user_name": initiator.get("userName"),
                        "account_id": initiator.get("accountId"),
                    }
                )
    return {
        "detection_id": event.get("id"),
        "category": event.get("category"),
        "type": event.get("type"),
        "status": event.get("status"),
        "occurrence_count": event.get("occurrence_count"),
        "resource": {
            "name": resource.get("name"),
            "type": resource.get("type"),
            "namespace": resource.get("namespace"),
            "region": resource.get("region"),
            "cloud_provider": resource.get("cloud_provider"),
            "cloud_account_id": resource.get("cloud_account_id"),
        },
        "initiators": initiators,
        "mitre_attacks": mitre,
    }
