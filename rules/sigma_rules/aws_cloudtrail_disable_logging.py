def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "cloudtrail.amazonaws.com",
            event.deep_get("eventName", default="")
            in ["StopLogging", "UpdateTrail", "DeleteTrail"],
        ]
    ):
        return True
    return False
