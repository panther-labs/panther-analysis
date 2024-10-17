from panther_aws_helpers import aws_rule_context


def rule(_):
    return True


def title(event):
    return (
        f"AWS [{event.get('eventName')}] for "
        f"[{event.deep_get('userIdentity', 'arn', default = '<arn_not_found>')}]"
        " from unmanaged IP Address."
    )


def alert_context(event):
    return aws_rule_context(event)
