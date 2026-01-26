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

    return (
        f"Proofpoint: Multiple Threats Detected ({active_count}) "
        f"- Email from {sender}"
    )


def alert_context(event):
    threats = []
    threat_types = set()
    classifications = set()

    for threat in event.get("threatsInfoMap", []):
        if threat.get("threatStatus") == "active":
            threat_dict = {
                "threat": threat.get("threat", "<UNKNOWN_THREAT>"),
                "threatType": threat.get(
                    "threatType", "<UNKNOWN_THREAT_TYPE>"
                ),
                "classification": threat.get(
                    "classification", "<UNKNOWN_CLASSIFICATION>"
                ),
                "threatID": threat.get("threatID", "<UNKNOWN_THREAT_ID>"),
            }
            threats.append(threat_dict)
            threat_types.add(threat_dict["threatType"])
            classifications.add(threat_dict["classification"])

    return {
        "sender": event.get("sender", "<UNKNOWN_SENDER>"),
        "senderIP": event.get("senderIP", "<UNKNOWN_IP>"),
        "recipients": event.get("recipient", []),
        "subject": event.get("subject", "<UNKNOWN_SUBJECT>"),
        "messageID": event.get("messageID", "<UNKNOWN_MESSAGE_ID>"),
        "quarantineFolder": event.get(
            "quarantineFolder", "<UNKNOWN_QUARANTINE_FOLDER>"
        ),
        "quarantineRule": event.get(
            "quarantineRule", "<UNKNOWN_QUARANTINE_RULE>"
        ),
        "malwareScore": event.get("malwareScore"),
        "phishScore": event.get("phishScore"),
        "threatCount": len(threats),
        "threatTypes": list(threat_types),
        "classifications": list(classifications),
        "threats": threats,
    }
