def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "ec2.amazonaws.com",
            event.deep_get("eventName", default="") == "CreateNetworkAclEntry",
        ]
    ):
        return True
    return False
