from panther_base_helpers import deep_get


def rule(event):
    return deep_get(event, "event", "OperationName") == "DeleteAPIClients" and bool(
        deep_get(event, "event", "Success")
    )


def title(event):
    user = deep_get(event, "event", "UserId")
    service = deep_get(event, "event", "ServiceName")
    return f"{user} deleted an API key in {service}"
