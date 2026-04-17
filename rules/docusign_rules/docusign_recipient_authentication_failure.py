from panther_docusign_helpers import docusign_alert_context, get_recipients


def rule(event):
    return event.get("event") == "recipient-authentication-failure"


def title(event):
    recipients = get_recipients(event)
    recipient = (
        [
            recipient
            for recipient in recipients
            if recipient.get("recipientId") == event.deep_get("data", "recipientId")
        ][0]
        if recipients
        else {}
    )
    recipient_email = recipient.get("email", "Unknown")
    envelope_id = event.deep_get("data", "envelopeId", default="Unknown")
    return (
        f"DocuSign recipient authentication failure for "
        f"[{recipient_email}] on envelope [{envelope_id}]"
    )


def alert_context(event):
    return docusign_alert_context(event)
