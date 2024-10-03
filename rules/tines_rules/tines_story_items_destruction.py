from global_filter_tines import filter_include_event
from panther_tines_helpers import tines_alert_context


def rule(event):
    if not filter_include_event(event):
        return False

    return event.get("operation_name", "<NO_OPERATION_NAME>") == "StoryItemsDestruction"


def title(event):
    operation = event.get("operation_name", "<NO_OPERATION_NAME>")
    user = event.get("user_email", "<NO_USER_EMAIL>")
    tines_instance = event.get("p_source_label", "<NO_SOURCE_LABEL>")

    return f"Tines [{operation}] performed by [{user}] on [{tines_instance}]."


def alert_context(event):
    return tines_alert_context(event)
