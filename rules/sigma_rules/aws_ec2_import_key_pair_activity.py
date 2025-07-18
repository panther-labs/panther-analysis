def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "ec2.amazonaws.com",
            event.deep_get("eventName", default="") == "ImportKeyPair",
        ]
    ):
        return True
    return False
