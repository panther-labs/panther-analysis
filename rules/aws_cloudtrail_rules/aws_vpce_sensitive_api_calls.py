from panther_aws_helpers import aws_rule_context

# Define sensitive API calls to monitor as a constant
SENSITIVE_APIS = {
    "ec2.amazonaws.com": [
        "DescribeInstances",
        "DescribeNetworkInterfaces",
        "CreateKeyPair",
        "ImportKeyPair",
        "RunInstances",
    ],
    "kms.amazonaws.com": ["Decrypt", "GenerateDataKey", "CreateKey", "ScheduleKeyDeletion"],
    "secretsmanager.amazonaws.com": [
        "GetSecretValue",
        "CreateSecret",
        "PutSecretValue",
        "DeleteSecret",
    ],
    "s3.amazonaws.com": ["ListAllMyBuckets", "DeleteBucketPolicy", "PutBucketPolicy"],
    "cloudtrail.amazonaws.com": ["StopLogging", "DeleteTrail", "UpdateTrail"],
}


def rule(event):
    # Check if this is a VPC Endpoint network activity event
    if event.get("eventType") != "AwsVpceEvent" or event.get("eventCategory") != "NetworkActivity":
        return False

    event_source = event.get("eventSource")
    event_name = event.get("eventName")

    if event_source in SENSITIVE_APIS and event_name in SENSITIVE_APIS[event_source]:
        return True

    return False


def title(event):
    # Use UDM actor_user which leverages the get_actor_user helper function
    # This properly handles various identity types including AssumedRole, Root, etc.
    actor_user = event.udm("actor_user")
    api_name = event.get("eventName", "unknown")
    service = event.get("eventSource", "unknown").split(".")[0]

    return (
        f"Sensitive AWS API [{api_name}] called via VPC Endpoint by [{actor_user}] "
        f"to service [{service}]"
    )


def alert_context(event):
    account_id = event.deep_get("userIdentity", "accountId", default="")

    context = aws_rule_context(event)
    context.update(
        {
            "account_id": account_id,
            "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
            "principal_type": event.deep_get("userIdentity", "type", default="unknown"),
            "actor_user": event.udm("actor_user"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "event_source": event.get("eventSource", "unknown"),
            "api_call": event.get("eventName", "unknown"),
            "resources": event.get("resources", []),
            "request_parameters": event.get("requestParameters", {}),
        }
    )

    return context
