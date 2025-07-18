def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "eks.amazonaws.com",
            event.deep_get("eventName", default="") in ["CreateCluster", "DeleteCluster"],
        ]
    ):
        return True
    return False
