import json

from panther_base_helpers import deep_get
from panther_oss_helpers import BadLookup, resource_lookup

# TODO: Once Detection Pipelines are merged, implement downgraded (INFO) case for multiple
#       global resource recorders.


def policy(resource):
    if (
        resource.get("GlobalRecorderCount", 0) == 0
        or "Recorders" not in resource
        or not bool(resource.get("Recorders"))
    ):
        return False

    for recorder_name in resource.get("Recorders", []):
        try:
            recorder = resource_lookup(recorder_name)
        except BadLookup:
            continue
        if isinstance(recorder, str):
            recorder = json.loads(recorder)
        resource_records_global_resources = bool(
            deep_get(recorder, "RecordingGroup", "IncludeGlobalResourceTypes")
            and deep_get(recorder, "Status", "Recording")
        )
        if resource_records_global_resources:
            return True
    return False
