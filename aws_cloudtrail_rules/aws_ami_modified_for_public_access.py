from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get, aws_rule_context


def rule(event):
    # Only check successful ModiyImageAttribute events
    if not aws_cloudtrail_success(event) or event.get("eventName") != "ModifyImageAttribute":
        return False

    added_perms = deep_get(
        event, "requestParameters", "launchPermission", "add", "items", default=[]
    )

    for item in added_perms:
        if item.get("group") == "all":
            return True

    return False


def alert_context(event):
    return aws_rule_context(event)
