from panther_aws_helpers import aws_rule_context


def rule(event):
    return (
        event.get("eventSource", "") == "iam.amazonaws.com"
        and event.get("eventName", "") == "UpdateLoginProfile"
        and not event.deep_get("requestParameters", "passwordResetRequired", default=False)
        and not event.deep_get("userIdentity", "arn", default="").endswith(
            f"/{event.deep_get('requestParameters', 'userName', default='')}"
        )
    )


def title(event):
    return (
        f"User [{event.deep_get('userIdentity', 'arn').split('/')[-1]}] "
        f"changed the password for "
        f"[{event.deep_get('requestParameters','userName')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
