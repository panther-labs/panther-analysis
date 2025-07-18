def rule(event):
    if all(
        [
            "admin" in event.deep_get("debugContext", "debugData", "requestUri", default=""),
            event.deep_get("securityContext", "isProxy", default="") == "true",
        ]
    ):
        return True
    return False
