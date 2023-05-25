from global_filter_tines import filter_include_event
from panther_base_helpers import deep_get
from panther_tines_helpers import tines_alert_context

ACTIONS = [
    "CustomCertificateAuthoritySet",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
    return action in ACTIONS


def title(event):
    action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
    return f"Tines: [{action}] " f"by [{deep_get(event, 'user_email', default='<NO_USEREMAIL>')}]"


def alert_context(event):
    return tines_alert_context(event)


def dedup(event):
    return (
        f"{deep_get(event, 'user_id', default='<NO_USERID>')}"
        "_"
        f"{deep_get(event, 'operation_name', default='<NO_OPERATION>')}"
    )
