def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "iam.amazonaws.com",
            event.deep_get("eventName", default="") in ["GetLoginProfile", "CreateLoginProfile"],
            "S3 Browser" in event.deep_get("userAgent", default=""),
        ]
    ):
        return True
    return False
