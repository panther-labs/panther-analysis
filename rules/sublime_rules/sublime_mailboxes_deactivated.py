from panther_sublime_helpers import sublime_alert_context


def rule(event):
    return event.get("type") == "message_source.deactivate_mailboxes"


def alert_context(event):
    return sublime_alert_context(event)
