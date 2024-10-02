from global_filter_tines import filter_include_event
from panther_tines_helpers import tines_alert_context

ACTIONS = [
    "SsoConfigurationDefaultSet",
    "SsoConfigurationOidcSet",
    "SsoConfigurationSamlSet",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = event.deep_get("operation_name", default="<NO_OPERATION_NAME>")
    return action in ACTIONS


def title(event):
    action = event.deep_get("operation_name", default="<NO_OPERATION_NAME>")
    return (
        f"Tines: [{action}] Setting "
        f"changed by [{event.deep_get('user_email', default='<NO_USEREMAIL>')}]"
    )


def alert_context(event):
    return tines_alert_context(event)


def dedup(event):
    return (
        f"{event.deep_get('user_id', default='<NO_USERID>')}"
        "_"
        f"{event.deep_get('operation_name', default='<NO_OPERATION>')}"
    )
