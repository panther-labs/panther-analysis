from panther_proofpoint_helpers import proofpoint_alert_context


def rule(event):
    # Check if quarantined for phish
    if event.get("quarantineRule") == "phish" or event.get("quarantineFolder") == "Phish":
        return True

    # Check for high phish score
    if event.get("phishScore", 0) >= 80:
        return True

    # Check threats map for phishing classification
    for threat in event.get("threatsInfoMap", []):
        if threat.get("classification") == "phish" and threat.get("threatStatus") == "active":
            return True

    return False


def severity(event):
    phish_score = event.get("phishScore", 0)

    if phish_score >= 95:
        return "CRITICAL"
    if phish_score >= 80:
        return "HIGH"
    return "DEFAULT"


def title(event):
    subject = event.get("subject", "<UNKNOWN_SUBJECT>")
    sender = event.get("sender", "<UNKNOWN_SENDER>")
    return f"Proofpoint: Phishing Email Detected from {sender} - [{subject}]"


def dedup(event):
    # Deduplicate by sender and threat type to group related phishing alerts
    sender = event.get("sender", "<UNKNOWN_SENDER>")
    quarantine_folder = event.get("quarantineFolder", "phish")
    return f"proofpoint:phishing:{sender}:{quarantine_folder}"


def alert_context(event):
    # Use the common helper with threat URLs for phishing detection
    context = proofpoint_alert_context(event, include_threat_url=True)
    context["headerFrom"] = event.get("headerFrom", "<UNKNOWN_HEADER_FROM>")
    return context
