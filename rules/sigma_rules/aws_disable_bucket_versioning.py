def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "s3.amazonaws.com",
            event.deep_get("eventName", default="") == "PutBucketVersioning",
            "Suspended" in event.deep_get("requestParameters", default=""),
        ]
    ):
        return True
    return False
