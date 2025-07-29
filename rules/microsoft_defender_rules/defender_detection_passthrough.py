from panther_base_helpers import deep_get


def rule(event):
    # Alert on any AlertInfo event
    return event.get("category") == "AdvancedHunting-AlertInfo"


def title(event):
    # Simple title with the native Defender alert title
    return f"Defender Alert: [{deep_get(event, "properties", "Title", default="Unknown")}]"


def alert_context(event):

    # Use the AlertId and tenantId to generate a URL to the alert in the Microsoft 365 Security
    # Center. The tenant ID is not completely necessary, but is helpful if a user is a member
    # of multiple tenants
    alert_id = deep_get(event, "properties", "AlertId", default="Unknown")
    tenant_id = deep_get(event, "tenantId", default="Unknown")
    if alert_id != "Unknown" and tenant_id != "Unknown":
        alert_url = f"https://security.microsoft.com/alerts/{alert_id}_1?tid={tenant_id}"
    else:
        alert_url = "Unknown"

    return {
        "AlertId": alert_id,
        "Name": deep_get(event, "properties", "Title", default="Unknown"),
        "Severity": deep_get(event, "properties", "Severity", default="Unknown"),
        "Source": deep_get(event, "properties", "DetectionSource", default="Unknown"),
        "ATT&CK Techniques": deep_get(event, "properties", "AttackTechniques", default="Unknown"),
        "Alert URL": alert_url,
    }


def severity(event):
    return deep_get(event, "properties", "Severity", default="Medium")


def dedup(event):
    return f"{deep_get(event, 'properties', 'AlertId', default='Unknown')} "
