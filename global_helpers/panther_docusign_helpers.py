def docusign_alert_context(event) -> dict:
    return {
        "envelope_id": event.deep_get("data", "envelopeId"),
        "email_blurb": event.deep_get("data", "emailBlurb"),
        "email_subject": event.deep_get("data", "emailSubject"),
        "envelope_documents": [
            doc.get("name") for doc in event.deep_get("data", "envelopeDocuments", default=[])
        ],
        "sender_name": event.deep_get("data", "sender", "userName"),
        "sender_email": event.deep_get("data", "sender", "email"),
        "sender_ip_address": event.deep_get("data", "sender", "ipAddress"),
        "user_id": event.deep_get("data", "userId"),
        "recipient_emails": get_recipient_emails(event),
    }


def get_recipients(event) -> list:
    recipient_types = (
        "agents",
        "carbonCopies",
        "certifiedDeliveries",
        "editors",
        "inPersonSigners",
        "intermediaries",
        "notaries",
        "seals",
        "signers",
        "witnesses",
    )
    recipients = []
    for recipient_type in recipient_types:
        recipients.extend(
            event.deep_get("data", "envelopeSummary", "recipients", recipient_type, default=[])
        )
    return recipients


def get_recipient_emails(event) -> list:
    recipients = get_recipients(event)
    return list(set(recipient.get("email") for recipient in recipients))
