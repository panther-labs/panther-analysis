from global_filter_azuresignin import filter_include_event
from panther_azuresignin_helpers import actor_user, azure_signin_alert_context
from panther_base_helpers import deep_get


def rule(event):
    if not filter_include_event(event):
        return False
    error_code = deep_get(event, "properties", "status", "errorCode", default=0)
    return error_code > 0


def title(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"
    return f"AzureSignIn: Multiple Failed LogIns for Principal [{principal}]"


def dedup(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"
    return principal


def alert_context(event):
    return azure_signin_alert_context(event)
