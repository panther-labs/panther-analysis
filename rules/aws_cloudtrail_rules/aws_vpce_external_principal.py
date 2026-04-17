from panther_aws_helpers import aws_rule_context


def rule(event):
    # Check if this is a VPC Endpoint network activity event
    if event.get("eventType") != "AwsVpceEvent" or event.get("eventCategory") != "NetworkActivity":
        return False

    # Look for external principal pattern (limited userIdentity field)
    user_identity = event.get("userIdentity", {})

    # If it's an AWS account type without full identity details, it could be an external principal
    if (
        user_identity.get("type") == "AWSAccount"
        and "arn" not in user_identity
        and "principalId" in user_identity
    ):
        # Get the account ID from the event and compare with the principal's account
        event_account = event.get("recipientAccountId")
        principal_account = user_identity.get("accountId")

        # If the accounts don't match, it's an external principal
        if event_account and principal_account and event_account != principal_account:
            return True

    return False


def title(event):
    # Use UDM actor_user which leverages the get_actor_user helper function
    # This properly handles various identity types including AssumedRole, Root, etc.
    actor_user = event.udm("actor_user")
    principal_account = event.deep_get("userIdentity", "accountId", default="unknown")
    event_account = event.get("recipientAccountId", "unknown")

    return (
        f"External Principal [{actor_user}] from account [{principal_account}] "
        f"accessing resources in account [{event_account}]"
    )


def alert_context(event):
    principal_account = event.deep_get("userIdentity", "accountId", default="")
    event_account = event.get("recipientAccountId", "")

    context = aws_rule_context(event)
    context.update(
        {
            "event_account": event_account,
            "principal_account": principal_account,
            "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "event_source": event.get("eventSource", "unknown"),
            "api_call": event.get("eventName", "unknown"),
            "resources": event.get("resources", []),
            "actor_user": event.udm("actor_user"),
        }
    )

    return context
