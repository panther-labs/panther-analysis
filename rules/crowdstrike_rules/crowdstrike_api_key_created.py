from panther_base_helpers import deep_get

def rule(event):
    return (
        deep_get(event, "event", "OperationName") == "CreateAPIClient"
        and deep_get(event, "event", "Success") == True
    )

def title(event):
    user = deep_get(event, "event", "UserId")
    service = deep_get(event, "event", "ServiceName")
    return f"{user} created a new API key in {service}"