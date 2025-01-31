from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


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


def dedup(event):
    return f"{event.deep_get('userIdentity','arn')}"


def alert_context(event):
    base = aws_rule_context(event)
    base["ip_accessKeyId"] = (
        event.get("sourceIpAddress", "<NO_IP_ADDRESS>")
        + ":"
        + event.deep_get(
            "responseElements", "accessKey", "accessKeyId", default="<NO_ACCESS_KEY_ID>"
        )
    )
    base["request_username"] = event.deep_get(
        "requestParameters", "userName", default="USERNAME_NOT_FOUND"
    )
    return base
