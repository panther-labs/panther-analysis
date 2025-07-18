def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "rds.amazonaws.com",
            event.deep_get("responseElements", "publiclyAccessible", default="") == "true",
            event.deep_get("eventName", default="") == "RestoreDBInstanceFromDBSnapshot",
        ]
    ):
        return True
    return False
