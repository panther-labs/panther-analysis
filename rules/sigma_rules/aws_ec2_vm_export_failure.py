def rule(event):
    if all(
        [
            event.deep_get("eventName", default="") == "CreateInstanceExportTask",
            event.deep_get("eventSource", default="") == "ec2.amazonaws.com",
            not any(
                [
                    event.deep_get("errorMessage", default="") != "",
                    event.deep_get("errorCode", default="") != "",
                    "Failure" in event.deep_get("responseElements", default=""),
                ]
            ),
        ]
    ):
        return True
    return False
