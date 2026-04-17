def rule(event):
    aws_service = event.deep_get("userIdentity", "type") == "AWSService"
    return all(
        [
            event.get("eventName") == "AssumeRole",
            event.deep_get("requestParameters", "roleArn"),
            not aws_service,
        ]
    )
