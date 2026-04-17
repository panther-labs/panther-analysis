from panther_core import PantherEvent


def rule(event) -> bool:
    return event.deep_get("state", "status") == "open"


def title(event: PantherEvent) -> str:
    alert_type = event.get("asset_type_string")
    # Use the first non-null field for the title of the alert
    alert_desc = (
        event.deep_get("data", "title") or event.get("type_string") or "<UNKNOWN ALERT TITLE>"
    )
    return f"{alert_type}: {alert_desc}" if alert_type else alert_desc


def description(event):
    return event.get("description") or "DEFAULT"


def dedup(event: PantherEvent) -> str:
    # Explicitly dedup on severity
    return f"({severity(event)}) {title(event)}"


def severity(event: PantherEvent) -> str:
    match event.deep_get("state", "risk_level", default="medium"):
        case "informational":
            return "INFO"
        case "low":
            return "LOW"
        case "medium":
            return "MEDIUM"
        case "high":
            return "HIGH"
        case "critical":
            return "CRITICAL"
        case _:
            return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    return {
        "asset": {
            "name": event.get("asset_name", "<UNKNOWN ASSET NAME>"),
            "type": event.get("asset_type", "<UNKNOWN TYPE>"),
            "category": event.get("asset_category", "<UNKNOWN CATEGORY>"),
        },
        "category": event.get("category", "<UNKNOWN CATEGORY>"),
        "cloud_provider": {
            "id": event.get("cloud_provider_id", "<UNKNOWN_CLOUD_PROVIDER_ID>"),
            "type": event.get("cloud_provider", "<UNKNOWN_CLOUD_PROVIDER>"),
        },
        "details": event.deep_get("data", "details", default=""),
        "orca_alert_id": event.deep_get("state", "alert_id", default="<UNKNOWN ALERT ID>"),
        "org_id": event.get("organization_id", "<UNKNOWN ORG ID>"),
    }


def runbook(event: PantherEvent) -> dict:
    return event.get("recommendation") or event.deep_get("data", "recommendation", default="")
