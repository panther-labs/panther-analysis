def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "lambda.amazonaws.com",
            event.deep_get("eventName", default="") == "CreateFunctionUrlConfig",
        ]
    ):
        return True
    return False
