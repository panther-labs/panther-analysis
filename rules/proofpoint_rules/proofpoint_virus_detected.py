from panther_proofpoint_helpers import extract_threats


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
    return f"Proofpoint: Virus Detected in Email from {sender} " f"- [{subject}]"


def dedup(event):
    # Deduplicate by sender and threat type to group related virus alerts
    sender = event.get("sender", "<UNKNOWN_SENDER>")
    quarantine_folder = event.get("quarantineFolder", "Virus")
    return f"proofpoint:virus:{sender}:{quarantine_folder}"


def alert_context(event):
    context = {
        "sender": event.get("sender", "<UNKNOWN_SENDER>"),
        "senderIP": event.get("senderIP", "<UNKNOWN_IP>"),
        "recipients": event.get("recipient", []),
        "subject": event.get("subject", "<UNKNOWN_SUBJECT>"),
        "messageID": event.get("messageID", "<UNKNOWN_MESSAGE_ID>"),
        "quarantineFolder": event.get("quarantineFolder", "<UNKNOWN_QUARANTINE_FOLDER>"),
        "quarantineRule": event.get("quarantineRule", "<UNKNOWN_QUARANTINE_RULE>"),
        "malwareScore": event.get("malwareScore", 0),
        "threats": extract_threats(event),
        "messageSize": event.get("messageSize", 0),
    }
    return context
