from global_filter_tines import filter_include_event
from panther_tines_helpers import tines_alert_context

ACTIONS = ["ActionsDisabledChange"]


def rule(event):
    if not filter_include_event(event):
        return False
    action = event.get("operation_name", "<NO_OPERATION_NAME>")
    return action in ACTIONS


def title(event):
    action = event.get("operation_name", "<NO_OPERATION_NAME>")
    actor = event.get("user_email", "<NO_USERNAME>")
    return f"Tines: {action} " f"by {actor}"


def alert_context(event):
    return tines_alert_context(event)
