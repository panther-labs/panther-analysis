from panther_docusign_helpers import docusign_alert_context


def rule(event):
    template_events = ["template-created", "template-modified", "template-deleted"]
    return event.get("event") in template_events


def title(event):
    event_type = event.get("event", "template-modified").split("-")[1]
    template_id = event.deep_get("data", "templateId", default="Unknown")
    user_id = event.deep_get("data", "userId", default="Unknown")

    action = event_type.replace("template-", "").replace("-", " ").title()
    return f"DocuSign template {action.lower()}: {template_id} by user {user_id}"


def severity(event):
    event_type = event.get("event")
    if event_type == "template-deleted":
        return "DEFAULT"
    if event_type == "template-modified":
        return "LOW"
    return "INFO"


def alert_context(event):
    return docusign_alert_context(event)
