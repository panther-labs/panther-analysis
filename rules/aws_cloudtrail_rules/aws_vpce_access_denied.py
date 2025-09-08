from panther_aws_helpers import aws_rule_context


def rule(event):
    # Check if this is a VPC Endpoint network activity event
    if event.get("eventType") != "AwsVpceEvent" or event.get("eventCategory") != "NetworkActivity":
        return False

    # Look for access denied errors
    if event.get("errorCode") == "VpceAccessDenied":
        return True

    return False


def title(event):
    actor_user = event.udm("actor_user")
    source_ip = event.get("sourceIPAddress", "unknown")
    service = event.get("eventSource", "unknown").split(".")[0]
    return f"VPC Endpoint Access Denied for [{actor_user}] from [{source_ip}] to [{service}]"


def alert_context(event):
    account_id = event.deep_get("userIdentity", "accountId", default="unknown")

    context = aws_rule_context(event)
    context.update(
        {
            "account_id": account_id,
            "principal_id": event.deep_get("userIdentity", "principalId", default="unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "event_source": event.get("eventSource", "unknown"),
            "api_call": event.get("eventName", "unknown"),
            "error_message": event.get("errorMessage", ""),
            "resources": event.get("resources", []),
            "actor_user": event.udm("actor_user"),
        }
    )

    return context
