from panther_base_helpers import aws_rule_context, deep_get
from panther_default import aws_cloudtrail_success


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
