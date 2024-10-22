from collections.abc import Mapping

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_base_helpers import deep_get

IS_SINGLE_USER_SHARE = False  # Used to adjust severity


def rule(event):
    if not aws_cloudtrail_success(event):
        return False

    # EC2 Volume snapshot made public
    if event.get("eventName") == "ModifySnapshotAttribute":
        parameters = event.get("requestParameters", {})
        if parameters.get("attributeType") != "CREATE_VOLUME_PERMISSION":
            return False

        items = deep_get(parameters, "createVolumePermission", "add", "items", default=[])
        for item in items:
            if not isinstance(item, (Mapping, dict)):
                continue
            if item.get("userId") or item.get("group") == "all":
                global IS_SINGLE_USER_SHARE  # pylint: disable=global-statement
                IS_SINGLE_USER_SHARE = "userId" in item  # Used for dynamic severity
                return True
        return False

    return False


def severity(_):
    # Set severity to INFO if only shared with a single user
    if IS_SINGLE_USER_SHARE:
        return "INFO"
    return "DEFAULT"


def alert_context(event):
    return aws_rule_context(event)
