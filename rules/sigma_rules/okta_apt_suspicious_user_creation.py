def rule(event):
    if all(
        [
            event.deep_get("eventtype", default="")
            in ["user.lifecycle.create", "user.lifecycle.activate"],
            "svc_network_backup" in event.deep_get("target", "user", "display", "name", default=""),
        ]
    ):
        return True
    return False
