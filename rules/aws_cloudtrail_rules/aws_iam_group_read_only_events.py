from panther_base_helpers import aws_rule_context

# arn allow list to suppress alerts
ARN_ALLOW_LIST = []

GROUP_ACTIONS = [
    "GetGroup",
    "GetGroupPolicy",
    "ListAttachedGroupPolicies",
    "ListGroupPolicies",
    "ListGroups",
    "ListGroupsForUser",
]


def rule(event):
    event_arn = event.udm("user_arn")
    # Return True if arn not in whitelist and event source is iam and event name is
    # present in read/list event_name list.
    if (
        event_arn not in ARN_ALLOW_LIST
        and event.udm("event_source") == "iam.amazonaws.com"
        and event.udm("event_name") in GROUP_ACTIONS
    ):
        # continue on with analysis
        return True
    return False


def title(event):
    return (
        f"{event.udm('user_arn')} "
        f"IAM user group activity event found: {event.udm('event_name')} "
        f"in account {event.udm('recipient_account_id')} "
        f"in region {event.udm('cloud_region')}."
    )


def dedup(event):
    # dedup via arn value
    return f"{event.udm('user_arn')}"


def alert_context(event):
    return aws_rule_context(event)
