def rule(event):
    return "ossec-rootkit" in event.get("name", "") and event.get("action") == "added"


def generate_alert_title(event):
    return f"ALERT: OSSEC rootkit detected on host [{event.get('hostIdentifier')}]"
