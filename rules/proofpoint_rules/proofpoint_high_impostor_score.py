def rule(event):
    # Alert on impostor scores of 50 or higher
    return event.get("impostorScore", 0) >= 50


def severity(event):
    impostor_score = event.get("impostorScore", 0)

    if impostor_score >= 80:
        return "CRITICAL"
    if impostor_score >= 65:
        return "HIGH"
    if impostor_score >= 50:
        return "MEDIUM"
    return "DEFAULT"


def title(event):
    sender = event.get("sender", "<UNKNOWN_SENDER>")
    impostor_score = event.get("impostorScore", 0)
    return (
        f"Proofpoint: High Impostor Score ({impostor_score}) "
        f"- Email from {sender}"
    )


def alert_context(event):
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
        "spamScore": event.get("spamScore"),
        "impostorScore": event.get("impostorScore"),
        "headerFrom": event.get("headerFrom", "<UNKNOWN_HEADER_FROM>"),
    }
