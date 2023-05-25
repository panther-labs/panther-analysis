from global_filter_tines import filter_include_event
from panther_base_helpers import deep_get
from panther_tines_helpers import tines_alert_context

ACTIONS = [
    "AuthenticationTokenCreation",
    # AuthenticationTokenDeletion does not include
    #  the scope of the deleted token.
    # Leaving deletion un-implemented for now
    # "AuthenticationTokenDeletion",
]


def rule(event):
    if not filter_include_event(event):
        return False
    action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
    is_tenant_token = deep_get(event, "inputs", "inputs", "isServiceToken", default=False)
    return all([action in ACTIONS, is_tenant_token])


def title(event):
    action = deep_get(event, "operation_name", default="<NO_OPERATION_NAME>")
    return (
        f"Tines: Tenant [{action}] "
        f"by [{deep_get(event, 'user_email', default='<NO_USEREMAIL>')}]"
    )


def alert_context(event):
    a_c = tines_alert_context(event)
    a_c["token_name"] = deep_get(event, "inputs", "inputs", "name", default="<NO_TOKENNAME>")
    return a_c


def dedup(event):
    return (
        f"{deep_get(event, 'user_id', default='<NO_USERID>')}"
        "_"
        f"{deep_get(event, 'operation_name', default='<NO_OPERATION>')}"
        "_"
        f"{deep_get(event, 'inputs', 'inputs', 'name', default='<NO_TOKENNAME>')}"
    )
