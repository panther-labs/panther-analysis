def rule(event):
    # Return True to match the log event and trigger an alert.
    aws_service = event.deep_get("userIdentity", "type") == "AWSService"
    return all(
        [
            event.get("eventName") == "AssumeRole",
            event.deep_get("requestParameters", "roleArn"),
            not aws_service
        ]
    )