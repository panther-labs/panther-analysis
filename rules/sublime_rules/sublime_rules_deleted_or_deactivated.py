from panther_sublime_helpers import sublime_alert_context

SUSPICIOUS_EVENTS = [
    "rules.delete",
    "rules.deactivate",
]


def rule(event):
    all_events = event.deep_walk("events", "type")
    return any(event in all_events for event in SUSPICIOUS_EVENTS)


def alert_context(event):
    return sublime_alert_context(event)
