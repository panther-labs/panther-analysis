from panther_base_helpers import aws_rule_context


def rule(event):
    # Return True to match the log event and trigger an alert.
    event_names = [
        "CreateTrafficMirrorFilter",
        "CreateTrafficMirrorFilterRule",
        "CreateTrafficMirrorSession",
        "CreateTrafficMirrorTarget",
        "DeleteTrafficMirrorFilter",
        "DeleteTrafficMirrorFilterRule",
        "DeleteTrafficMirrorSession",
        "DeleteTrafficMirrorTarget",
        "DescribeTrafficMirrorFilters",
        "DescribeTrafficMirrorSessions",
        "DescribeTrafficMirrorTargets",
        "ModifyTrafficMirrorFilterNetworkServices",
        "ModifyTrafficMirrorFilterRule",
        "ModifyTrafficMirrorSession",
    ]
    if event.udm("invoked_by", default="").endswith(".amazonaws.com"):
        return False
    return (
        event.udm("event_source") == "ec2.amazonaws.com" and event.udm("event_name") in event_names
    )


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will
    # act as deduplication string.
    return (
        f"{event.udm('user_arn')} ec2 activity found for "
        f"{event.udm('event_name')} in account {event.udm('recipient_account_id')} "
        f"in region {event.udm('cloud_region')}."
    )


def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # Dedupe based on user identity, to not include multiple events from the same identity.
    user_arn = event.udm("user_arn") or "no-user-identity-provided"
    return user_arn


def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included
    #  in the alert sent to the SNS/SQS/Webhook destination
    return aws_rule_context(event)
