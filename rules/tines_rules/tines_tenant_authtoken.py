from panther_tines_helpers import tines_alert_context

ACTIONS = [
    "AuthenticationTokenCreation",
    # AuthenticationTokenDeletion does not include
    #  the scope of the deleted token.
    # Leaving deletion un-implemented for now
    # "AuthenticationTokenDeletion",
]


def rule(event):

    action = event.get("operation_name", "<NO_OPERATION_NAME>")
    is_tenant_token = event.deep_get("inputs", "inputs", "isServiceToken", default=False)
    return all([action in ACTIONS, is_tenant_token])


def title(event):
    action = event.get("operation_name", "<NO_OPERATION_NAME>")
    return (
        f"Tines: Tenant [{action}] "
        f"by [{event.deep_get('user_email', default='<NO_USEREMAIL>')}]"
    )


def alert_context(event):
    a_c = tines_alert_context(event)
    a_c["token_name"] = event.deep_get("inputs", "inputs", "name", default="<NO_TOKENNAME>")
    return a_c


def dedup(event):
    return (
        f"{event.deep_get('user_id', default='<NO_USERID>')}"
        "_"
        f"{event.deep_get('operation_name', default='<NO_OPERATION>')}"
        "_"
        f"{event.deep_get('inputs', 'inputs', 'name', default='<NO_TOKENNAME>')}"
    )
