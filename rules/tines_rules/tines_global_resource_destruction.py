from global_filter_tines import filter_include_event
from panther_base_helpers import deep_get
from panther_tines_helpers import tines_alert_context


def rule(event):
    if not filter_include_event(event):
        return False

    return deep_get(event, "operation_name", default="NO_OPERATION_NAME") == "GlobalResourceDestruction"


def title(event):
    operation = deep_get(event, "operation_name", default="NO_OPERATION_NAME")
    user = deep_get(event, "user_email", default="NO_USER_EMAIL")
    tines_instance = deep_get(event, "p_source_label", default="NO_SOURCE_LABEL")
    return f"Tines [{operation}] by [{user}] on [{tines_instance}]"


def alert_context(event):
    return tines_alert_context(event)
