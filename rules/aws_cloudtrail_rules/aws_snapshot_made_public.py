from collections.abc import Mapping

from panther_base_helpers import aws_rule_context, deep_get
from panther_default import aws_cloudtrail_success


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
            if item.get("group") == "all":
                return True
        return False

    # RDS snapshot made public
    if event.get("eventName") == "ModifyDBClusterSnapshotAttribute":
        return "all" in deep_get(event, "requestParameters", "valuesToAdd", default=[])

    return False


def alert_context(event):
    return aws_rule_context(event)
