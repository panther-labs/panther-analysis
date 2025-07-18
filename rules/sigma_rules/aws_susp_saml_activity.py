def rule(event):
    if any(
        [
            all(
                [
                    event.deep_get("eventSource", default="") == "sts.amazonaws.com",
                    event.deep_get("eventName", default="") == "AssumeRoleWithSAML",
                ]
            ),
            all(
                [
                    event.deep_get("eventSource", default="") == "iam.amazonaws.com",
                    event.deep_get("eventName", default="") == "UpdateSAMLProvider",
                ]
            ),
        ]
    ):
        return True
    return False
