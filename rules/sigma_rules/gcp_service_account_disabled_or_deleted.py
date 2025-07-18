def rule(event):
    if any(
        [
            event.deep_get("protoPayload", "methodName", default="").endswith(
                ".serviceAccounts.disable"
            ),
            event.deep_get("protoPayload", "methodName", default="").endswith(
                ".serviceAccounts.delete"
            ),
        ]
    ):
        return True
    return False
