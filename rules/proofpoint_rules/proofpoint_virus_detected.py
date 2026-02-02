from panther_proofpoint_helpers import proofpoint_alert_context


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
    # Use the common helper and extend with virus-specific fields
    context = proofpoint_alert_context(event)
    context["messageSize"] = event.get("messageSize", 0)
    return context
