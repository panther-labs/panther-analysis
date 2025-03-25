from panther_aws_helpers import aws_rule_context


def rule(event):
    return event.get("eventName") == "EnableRegion"


def title(event):
    return (
        f"AWS CloudTrail region [{event.deep_get('requestParameters', 'RegionName')}] "
        f"enabled by user [{event.udm('actor_user')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
