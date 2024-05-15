from panther_base_helpers import aws_rule_context


def rule(event):
    if event.udm("event_name") == "ModifyInstanceAttribute" and event.udm("user_data"):
        return True
    return False


def title(event):
    return (
        f"[{event.udm('user_arn')}] "
        "modified the startup script for "
        f" [{event.udm('instance_id')}] "
        f"in [{event.udm('recipient_account_id')}] - [{event.get('cloud_region')}]"
    )


def dedup(event):
    return event.udm("instance_id")


def alert_context(event):
    return aws_rule_context(event)
