ALERT_URL = ""


def rule(event):
    # Alert on any AlertInfo event
    return event.get("category") == "AdvancedHunting-AlertInfo"


def title(event):
    # Simple title with the native Defender alert title
    return f"Defender Alert: [{event.deep_get('properties', 'Title', default='Unknown')}]"


def alert_context(event):

    # pylint: disable=global-statement
    global ALERT_URL

    # Use the AlertId and tenantId to generate a URL to the alert in the Microsoft 365 Security
    # Center. The tenant ID is not completely necessary, but is helpful if a user is a member
    # of multiple tenants
    alert_id = event.deep_get("properties", "AlertId", default="Unknown")
    tenant_id = event.deep_get("tenantId", default="Unknown")
    if alert_id != "Unknown" and tenant_id != "Unknown":
        ALERT_URL = f"https://security.microsoft.com/alerts/{alert_id}?tid={tenant_id}"
    else:
        ALERT_URL = ""

    return {
        "AlertId": alert_id,
        "Name": event.deep_get("properties", "Title", default="Unknown"),
        "Severity": event.deep_get("properties", "Severity", default="Unknown"),
        "Source": event.deep_get("properties", "DetectionSource", default="Unknown"),
        "ATT&CK Techniques": event.deep_get("properties", "AttackTechniques", default="Unknown"),
        "Alert URL": ALERT_URL,
    }


def reference(_):

    # If the alert ID is not found, return the Microsoft Defender documentation for the
    # AlertInfo table.
    if ALERT_URL:
        return ALERT_URL

    return "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table"


def severity(event):
    return event.deep_get("properties", "Severity", default="MEDIUM")


def dedup(event):
    return f"{event.deep_get('properties', 'AlertId', default='Unknown')} "
