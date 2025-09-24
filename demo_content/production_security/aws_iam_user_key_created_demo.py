from panther_aws_helpers import aws_cloudtrail_success


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") == "CreateAccessKey"
        and (
            not event.deep_get("userIdentity", "arn", default="").endswith(
                f"user/{event.deep_get('responseElements', 'accessKey', 'userName', default='')}"
            )
        )
    )


def title(event):
    return (
        f"[{event.deep_get('userIdentity','arn')}]"
        " created API keys for "
        f"[{event.deep_get('responseElements','accessKey','userName', default = '')}]"
    )


def runbook(event):
    return f"""
    Check if the key was used. Query the aws_cloudtrail table for events using the new access key ({event.deep_get("responseElements", "accessKey", "accessKeyId", default="key not found")}) starting from ({event.get("eventTime", "")}) and ~2 hours after. Look for privilege escalation or other techniques used by the attacker.
    """


def alert_context(event):
    context = {
        "target": event.deep_get("requestParameters", "userName", default=""),
        "actor": event.deep_get("userIdentity", "arn", default=""),
        "timestamp": event.get("eventTime", ""),
        "parameters": event.deep_get("requestParameters", default={}),
        "access_key_id": event.deep_get("responseElements", "accessKey", "accessKeyId", default=""),
        "action": event.get("eventName", ""),
    }
    return context
