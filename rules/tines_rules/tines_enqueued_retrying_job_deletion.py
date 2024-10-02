from global_filter_tines import filter_include_event
from panther_tines_helpers import tines_alert_context


def rule(event):
    if not filter_include_event(event):
        return False

    return event.deep_get("operation_name", default="<NO_OPERATION_NAME>") in [
        "JobsQueuedDeletion",
        "JobsRetryingDeletion",
    ]


def title(event):
    operation = event.deep_get("operation_name", default="<NO_OPERATION_NAME>")
    user = event.deep_get("user_email", default="<NO_USER_EMAIL>")
    tines_instance = event.deep_get("p_source_label", default="<NO_SOURCE_LABEL>")

    return f"Tines [{operation}] performed by [{user}] on [{tines_instance}]."


def alert_context(event):
    return tines_alert_context(event)
