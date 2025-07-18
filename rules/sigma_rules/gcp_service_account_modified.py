def rule(event):
    if any(
        [
            event.deep_get("protoPayload", "methodName", default="").endswith(
                ".serviceAccounts.patch"
            ),
            event.deep_get("protoPayload", "methodName", default="").endswith(
                ".serviceAccounts.create"
            ),
            event.deep_get("protoPayload", "methodName", default="").endswith(
                ".serviceAccounts.update"
            ),
            event.deep_get("protoPayload", "methodName", default="").endswith(
                ".serviceAccounts.enable"
            ),
            event.deep_get("protoPayload", "methodName", default="").endswith(
                ".serviceAccounts.undelete"
            ),
        ]
    ):
        return True
    return False
