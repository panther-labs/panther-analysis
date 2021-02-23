from collections.abc import Mapping
from panther_base_helpers import deep_get


def rule(event):
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
