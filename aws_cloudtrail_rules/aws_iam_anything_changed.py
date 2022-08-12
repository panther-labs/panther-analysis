from panther import aws_cloudtrail_success
from panther_base_helpers import aws_rule_context

IAM_CHANGE_ACTIONS = [
    "Add",
    "Attach",
    "Change",
    "Create",
    "Deactivate",
    "Delete",
    "Detach",
    "Enable",
    "Put",
    "Remove",
    "Set",
    "Update",
    "Upload",
]


def rule(event):
    # Only check IAM events, as the next check is relatively computationally
    # expensive and can often be skipped
    if not aws_cloudtrail_success(event) or event.get("eventSource") != "iam.amazonaws.com":
        return False

    return any((event.get("eventName", "").startswith(action) for action in IAM_CHANGE_ACTIONS))


def alert_context(event):
    return aws_rule_context(event)
