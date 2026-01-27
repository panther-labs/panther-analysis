from panther_proofpoint_helpers import extract_threats


def rule(event):
    # Must have at least 2 active threats
    active_count = 0
    for threat in event.get("threatsInfoMap", []):
        if threat.get("threatStatus") == "active":
            active_count += 1

    return active_count >= 2


def severity(event):
    active_count = 0
    for threat in event.get("threatsInfoMap", []):
        if threat.get("threatStatus") == "active":
            active_count += 1

    if active_count >= 5:
        return "CRITICAL"
    if active_count >= 3:
        return "HIGH"
    if active_count >= 2:
        return "MEDIUM"
    return "DEFAULT"


def title(event):
    sender = event.get("sender", "<UNKNOWN_SENDER>")

    active_count = 0
    for threat in event.get("threatsInfoMap", []):
        if threat.get("threatStatus") == "active":
            active_count += 1

    return f"Proofpoint: Multiple Threats Detected ({active_count}) " f"- Email from {sender}"


def alert_context(event):
    # Extract all threats using the helper
    all_threats = extract_threats(event)

    # Filter to only active threats
    active_threats = [t for t in all_threats if t.get("threatStatus") == "active"]
    threat_types = set(t.get("threatType") for t in active_threats if t.get("threatType"))
    classifications = set(
        t.get("classification") for t in active_threats if t.get("classification")
    )

    return {
        "sender": event.get("sender", "<UNKNOWN_SENDER>"),
        "senderIP": event.get("senderIP", "<UNKNOWN_IP>"),
        "recipients": event.get("recipient", []),
        "subject": event.get("subject", "<UNKNOWN_SUBJECT>"),
        "messageID": event.get("messageID", "<UNKNOWN_MESSAGE_ID>"),
        "quarantineFolder": event.get("quarantineFolder", "<UNKNOWN_QUARANTINE_FOLDER>"),
        "quarantineRule": event.get("quarantineRule", "<UNKNOWN_QUARANTINE_RULE>"),
        "malwareScore": event.get("malwareScore", 0),
        "phishScore": event.get("phishScore", 0),
        "threatCount": len(active_threats),
        "threatTypes": list(threat_types),
        "classifications": list(classifications),
        "threats": active_threats,
    }
