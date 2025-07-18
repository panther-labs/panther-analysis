def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "rds.amazonaws.com",
            event.deep_get(
                "responseElements", "pendingModifiedValues", "masterUserPassword", default=""
            )
            != "",
            event.deep_get("eventName", default="") == "ModifyDBInstance",
        ]
    ):
        return True
    return False
