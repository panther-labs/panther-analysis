def rule(event):
    threats_info = event.get("threatsInfoMap", [])

    # Must have at least 2 active threats
    active_threats = [threat for threat in threats_info if threat.get("threatStatus") == "active"]

    return len(active_threats) >= 2


def severity(event):
    threats_info = event.get("threatsInfoMap", [])
    active_threats = [threat for threat in threats_info if threat.get("threatStatus") == "active"]

    threat_count = len(active_threats)

    if threat_count >= 5:
        return "CRITICAL"
    if threat_count >= 3:
        return "HIGH"
    if threat_count >= 2:
        return "MEDIUM"
    return "DEFAULT"


def title(event):
    sender = event.get("sender", "<UNKNOWN_SENDER>")
    threats_info = event.get("threatsInfoMap", [])
    active_threats = [threat for threat in threats_info if threat.get("threatStatus") == "active"]
    threat_count = len(active_threats)

    return f"Proofpoint: Multiple Threats Detected ({threat_count}) - Email from {sender}"


def alert_context(event):
    threats = []
    threat_types = set()
    classifications = set()

    threats_info = event.get("threatsInfoMap", [])
    if not isinstance(threats_info, list):
        threats_info = []

    for threat in threats_info:
        if threat.get("threatStatus") == "active":
            threats.append(
                {
                    "threat": threat.get("threat", "<UNKNOWN_THREAT>"),
                    "threatType": threat.get("threatType", "<UNKNOWN_THREAT_TYPE>"),
                    "classification": threat.get("classification", "<UNKNOWN_CLASSIFICATION>"),
                    "threatID": threat.get("threatID", "<UNKNOWN_THREAT_ID>"),
                }
            )
            threat_types.add(threat.get("threatType", "<UNKNOWN_THREAT_TYPE>"))
            classifications.add(threat.get("classification", "<UNKNOWN_CLASSIFICATION>"))

    return {
        "sender": event.get("sender", "<UNKNOWN_SENDER>"),
        "senderIP": event.get("senderIP", "<UNKNOWN_IP>"),
        "recipients": event.get("recipient", []),
        "subject": event.get("subject", "<UNKNOWN_SUBJECT>"),
        "threatCount": len(threats),
        "threatTypes": list(threat_types),
        "classifications": list(classifications),
        "threats": threats,
        "malwareScore": event.get("malwareScore"),
        "phishScore": event.get("phishScore"),
        "quarantineFolder": event.get("quarantineFolder", "<UNKNOWN_QUARANTINE_FOLDER>"),
        "quarantineRule": event.get("quarantineRule", "<UNKNOWN_QUARANTINE_RULE>"),
        "messageID": event.get("messageID", "<UNKNOWN_MESSAGE_ID>"),
    }
