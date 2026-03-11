from panther_proofpoint_helpers import proofpoint_alert_context


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
    return f"Proofpoint: High Impostor Score ({impostor_score}) " f"- Email from {sender}"


def alert_context(event):
    # Use the common helper and extend with impostor-specific fields
    context = proofpoint_alert_context(event)
    context.update(
        {
            "spamScore": event.get("spamScore", 0),
            "impostorScore": event.get("impostorScore", 0),
            "headerFrom": event.get("headerFrom", "<UNKNOWN_HEADER_FROM>"),
        }
    )
    return context
