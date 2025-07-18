def rule(event):
    if all(
        [
            event.deep_get("userIdentity", "type", default="") == "AssumedRole",
            event.deep_get("userIdentity", "sessionContext", "sessionIssuer", "type", default="")
            == "Role",
        ]
    ):
        return True
    return False
