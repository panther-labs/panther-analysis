from panther_thinkstcanary_helpers import additional_details


def rule(event):
    return event.get("AlertType") == "CanarytokenIncident"


def title(event):
    return event.get("Intro", "Canary Token Incident")


def alert_context(event):
    return additional_details(event)
