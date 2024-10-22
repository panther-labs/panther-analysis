from panther_thinkstcanary_helpers import additional_details


def rule(event):
    return event.get("AlertType") == "CanaryIncident"


def title(event):
    return event.get("Intro", "Canary Incident")


def alert_context(event):
    return additional_details(event)
