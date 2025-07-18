def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "lambda.amazonaws.com",
            event.deep_get("eventName", default="").startswith("UpdateFunctionConfiguration"),
            event.deep_get("requestParameters", "layers", default="") != "",
        ]
    ):
        return True
    return False
