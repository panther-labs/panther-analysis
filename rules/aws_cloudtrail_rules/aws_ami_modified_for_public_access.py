from panther_detection_helpers.caching import check_account_age

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context



def rule(event):
    # Only check successful ModiyImageAttribute events
    if not aws_cloudtrail_success(event) or event.get("eventName") != "ModifyImageAttribute":
        return False

    added_perms = event.deep_get(
        "requestParameters", "launchPermission", "add", "items", default=[{}]
    )

    for item in added_perms:
        if item.get("group") == "all":
            return True
        if check_account_age(item.get("userId")):  # checking if the account is new
            return True

    return False


def alert_context(event):
    return aws_rule_context(event)
