def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "rds.amazonaws.com",
            event.deep_get("eventName", default="") in ["ModifyDBCluster", "DeleteDBCluster"],
        ]
    ):
        return True
    return False
