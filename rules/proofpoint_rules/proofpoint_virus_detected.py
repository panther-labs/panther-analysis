def rule(event):
    quarantine_rule = event.get("quarantineRule", "")
    quarantine_folder = event.get("quarantineFolder", "")

    # Alert if either virus-related quarantine indicators are present
    # OR if there's a high malware score (covers edge cases)
    if quarantine_rule == "notcleaned" or quarantine_folder == "Virus":
        return True

    # Backup check: also alert on very high malware scores that indicate virus
    if event.get("malwareScore", 0) >= 95:
        return True

    return False


def severity(event):
    malware_score = event.get("malwareScore", 0)

    if malware_score >= 95:
        return "CRITICAL"
    if malware_score >= 85:
        return "HIGH"
    return "DEFAULT"


def title(event):
    subject = event.get("subject", "<UNKNOWN_SUBJECT>")
    sender = event.get("sender", "<UNKNOWN_SENDER>")
    return f"Proofpoint: Virus Detected in Email from {sender} - [{subject}]"


def alert_context(event):
    threats = []
    threats_info = event.get("threatsInfoMap", [])
    if not isinstance(threats_info, list):
        threats_info = []

    for threat in threats_info:
        if hasattr(threat, "get"):
            threats.append(
                {
                    "threat": threat.get("threat", "<UNKNOWN_THREAT>"),
                    "threatType": threat.get("threatType", "<UNKNOWN_THREAT_TYPE>"),
                    "classification": threat.get("classification", "<UNKNOWN_CLASSIFICATION>"),
                    "threatStatus": threat.get("threatStatus", "<UNKNOWN_THREAT_STATUS>"),
                }
            )

    return {
        "sender": event.get("sender", "<UNKNOWN_SENDER>"),
        "senderIP": event.get("senderIP", "<UNKNOWN_IP>"),
        "recipients": event.get("recipient", []),
        "subject": event.get("subject", "<UNKNOWN_SUBJECT>"),
        "malwareScore": event.get("malwareScore"),
        "quarantineFolder": event.get("quarantineFolder", "<UNKNOWN_QUARANTINE_FOLDER>"),
        "quarantineRule": event.get("quarantineRule", "<UNKNOWN_QUARANTINE_RULE>"),
        "threats": threats,
        "messageID": event.get("messageID", "<UNKNOWN_MESSAGE_ID>"),
        "messageSize": event.get("messageSize"),
    }
