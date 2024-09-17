from panther_sublime_helpers import sublime_alert_context


def rule(event):
    all_events = event.deep_walk("events", "type")
    return "message_source.deactivate_mailboxes" in all_events


def alert_context(event):
    return sublime_alert_context(event)
