from datetime import timedelta

from panther_base_helpers import deep_get
from panther_oss_helpers import resolve_timestamp_string

AWS_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_TIME = "0001-01-01T00:00:00Z"
MAX_SECONDS_TO_AUTOGEN_KEY = timedelta(seconds=7)


def policy(resource):
    # If a user is less than 4 hours old, it may not have a credential report generated yet.
    # It will be re-scanned periodically until a credential report is found, at which point this
    # policy will be properly evaluated.
    if not resource.get("CredentialReport"):
        return True

    key_rot = deep_get(resource, "CredentialReport", "AccessKey1LastRotated")
    if key_rot == DEFAULT_TIME:
        return True

    create = resource.get("TimeCreated", "")
    key_rot_date = resolve_timestamp_string(key_rot)
    create_date = resolve_timestamp_string(create)

    if not key_rot_date or not create_date:
        return True

    return (key_rot_date - create_date) >= MAX_SECONDS_TO_AUTOGEN_KEY
