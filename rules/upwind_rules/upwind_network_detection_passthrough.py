SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Upwind network detections cover port scans, DoS activity, DNS anomalies,
# DNS-over-HTTPS abuse, and other anomalous network behaviors.
NETWORK_KEYWORDS = ("network",)


def rule(event):
    category = event.get("category", "").lower()
    return (
        event.get("severity", "").upper() in SEVERITY_MAP
        and any(kw in category for kw in NETWORK_KEYWORDS)
    )


def title(event):
    return f"[Upwind Network]: {event.get('title', '<NO TITLE>')}"


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
            "internet_facing": resource.get("internet_exposure", {})
            .get("ingress", {})
            .get("active_communication"),
        },
        "mitre_attacks": mitre,
    }
