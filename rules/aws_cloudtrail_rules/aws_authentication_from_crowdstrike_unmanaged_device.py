from panther_base_helpers import deep_get, aws_rule_context

def rule(event):
    return True

def title(event):
    return (
        f"AWS [{event.get('eventName')}] for "
        f"[{deep_get(event, 'userIdentity', 'arn', default = '<arn_not_found>')}]"
        " from unmanaged device."
    )

def alert_context(event):
    return aws_rule_context(event)