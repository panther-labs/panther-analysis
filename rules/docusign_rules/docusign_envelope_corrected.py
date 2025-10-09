from panther_docusign_helpers import docusign_alert_context


def rule(event):
    return event.get("event") == "envelope-corrected"


def title(event):
    envelope_id = event.deep_get("data", "envelopeId", default="Unknown")
    sender_email = event.deep_get("data", "sender", "email", default="Unknown")
    return f"DocuSign envelope [{envelope_id}] corrected by [{sender_email}]"


def alert_context(event):
    return docusign_alert_context(event)
