from panther_sublime_helpers import sublime_alert_context

SUSPICIOUS_EVENTS = [
    "rules.delete",
    "rules.deactivate",
]


def rule(event):
    return event.get('type') in SUSPICIOUS_EVENTS


def alert_context(event):
    return sublime_alert_context(event)
