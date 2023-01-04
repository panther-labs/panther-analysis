from panther_base_helpers import aws_rule_context


def rule(event):
    arn_whitelist = []
    arn = event.get("userIdentity", {}).get("arn", "<NO_ARN_FOUND>")
    # Return True if arn not in whitelist and event source is iam and event name is
    # present in read/list event_name list.
    event_names = [
        "GetGroup",
        "GetGroupPolicy",
        "ListAttachedGroupPolicies",
        "ListGroupPolicies",
        "ListGroups",
        "ListGroupsForUser",
    ]
    if (
        arn not in arn_whitelist
        and event.get("eventSource", "<NO_EVENT_SOURCE_FOUND>") == "iam.amazonaws.com"
        and event.get("eventName", "<NO_EVENT_NAME_FOUND>") in event_names
    ):
        # continue on with analysis
        return True
    return False


def title(event):
    return (
        f"{event.get('userIdentity',{}).get('arn','<NO_ARN_FOUND>')} "
        f"IAM user group activity event found: {event.get('eventName', '<NO_EVENT_NAME_FOUND>')} "
        f"in account {event.get('recipientAccountId', '<NO_RECIPIENT_ACCT_ID_FOUND>')} "
        f"in region {event.get('awsRegion', '<NO_AWS_REGION_FOUND>')}."
    )


def dedup(event):
    # dedup via arn value
    return f"{event.get('userIdentity',{}).get('arn','<NO_ARN_FOUND>')}"


def alert_context(event):
    return aws_rule_context(event)
