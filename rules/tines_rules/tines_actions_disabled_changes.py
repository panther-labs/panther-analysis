from global_filter_tines import filter_include_event
from panther_base_helpers import deep_get
from panther_tines_helpers import tines_alert_context

ACTIONS = ["ActionsDisabledChange"]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
    return action in ACTIONS


def title(event):
    action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
    actor = deep_get(event, "user_email", default="<NO_USERNAME>")
    return f"Tines: {action} " f"by {actor}"


def alert_context(event):
    return tines_alert_context(event)
