def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "ecs.amazonaws.com",
            event.deep_get("eventName", default="")
            in ["DescribeTaskDefinition", "RegisterTaskDefinition", "RunTask"],
            "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
            in event.deep_get("requestParameters", "containerDefinitions", "command", default=""),
        ]
    ):
        return True
    return False
