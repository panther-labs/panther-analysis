def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "ec2.amazonaws.com",
            event.deep_get("eventName", default="") == "DisableEbsEncryptionByDefault",
        ]
    ):
        return True
    return False
