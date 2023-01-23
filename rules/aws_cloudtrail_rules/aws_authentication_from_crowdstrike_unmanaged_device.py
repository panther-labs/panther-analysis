from panther_base_helpers import aws_rule_context, deep_get


def rule(_):
    return True


def title(event):
    return (
        f"AWS [{event.get('eventName')}] for "
        f"[{deep_get(event, 'userIdentity', 'arn', default = '<arn_not_found>')}]"
        " from unmanaged device."
    )


def alert_context(event):
    return aws_rule_context(event)
