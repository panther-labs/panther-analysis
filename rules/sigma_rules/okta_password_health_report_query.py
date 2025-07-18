def rule(event):
    if "/reports/password-health/" in event.deep_get(
        "debugContext", "debugData", "requestUri", default=""
    ):
        return True
    return False
