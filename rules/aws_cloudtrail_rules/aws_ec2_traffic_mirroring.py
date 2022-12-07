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
    return (
        event.get("eventSource", "") == "ec2.amazonaws.com"
        and event.get("eventName", "") in event_names
    )


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will
    # act as deduplication string.
    return (
        f"{event.get('userIdentity',{}).get('arn','no-type')} ec2 activity found for "
        f"{event.get('eventName')} in account {event.get('recipientAccountId')} "
        f"in region {event.get('awsRegion')}."
    )


def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # Dedupe based on user identity, to not include multiple events from the same identity.
    return f"{event.get('userIdentity',{}).get('arn','no-user-identity-provided')}"


def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included
    #  in the alert sent to the SNS/SQS/Webhook destination
    return aws_rule_context(event)
