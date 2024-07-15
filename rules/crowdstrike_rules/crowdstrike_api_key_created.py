def rule(event):
    return all(
        [
            event.deep_get("event", "OperationName") == "CreateAPIClient",
            event.deep_get("event", "Success"),
        ]
    )


def title(event):
    user = event.deep_get("event", "UserId")
    service = event.deep_get("event", "ServiceName")
    return f"{user} created a new API key in {service}"
