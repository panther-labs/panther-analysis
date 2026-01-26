def rule(event):
    # Check if quarantined for phish
    if event.get("quarantineRule") == "phish" or event.get("quarantineFolder") == "Phish":
        return True

    # Check for high phish score
    if event.get("phishScore", 0) >= 80:
        return True

    # Check threats map for phishing classification
    for threat in event.get("threatsInfoMap", []):
        if (
            threat.get("classification") == "phish"
            and threat.get("threatStatus") == "active"
        ):
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


def alert_context(event):
    threats = []
    for threat in event.get("threatsInfoMap", []):
        threats.append(
            {
                "threat": threat.get("threat", "<UNKNOWN_THREAT>"),
                "threatType": threat.get(
                    "threatType", "<UNKNOWN_THREAT_TYPE>"
                ),
                "classification": threat.get(
                    "classification", "<UNKNOWN_CLASSIFICATION>"
                ),
                "threatStatus": threat.get(
                    "threatStatus", "<UNKNOWN_THREAT_STATUS>"
                ),
                "threatUrl": threat.get("threatUrl"),
            }
        )

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
        "phishScore": event.get("phishScore"),
        "malwareScore": event.get("malwareScore"),
        "threats": threats,
        "headerFrom": event.get("headerFrom", "<UNKNOWN_HEADER_FROM>"),
    }
