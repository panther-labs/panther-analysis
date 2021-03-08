from datetime import datetime, timedelta
from panther_base_helpers import deep_get

AWS_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PANTHER_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_TIME = "0001-01-01T00:00:00Z"
MAX_SECONDS_TO_AUTOGEN_KEY = timedelta(seconds=7)


def policy(resource):
    # If a user is less than 4 hours old, it may not have a credential report generated yet.
    # It will be re-scanned periodically until a credential report is found, at which point this
    # policy will be properly evaluated.
    if not resource["CredentialReport"]:
        return True

    key_rot = deep_get(resource, "CredentialReport", "AccessKey1LastRotated")
    if key_rot == DEFAULT_TIME:
        return True

    create = resource["TimeCreated"]
    key_rot_date = datetime.strptime(key_rot, AWS_TIME_FORMAT)
    try:
        create_date = datetime.strptime(create, PANTHER_TIME_FORMAT)
    except ValueError:
        create_date = datetime.strptime(create, AWS_TIME_FORMAT)

    return (key_rot_date - create_date) >= MAX_SECONDS_TO_AUTOGEN_KEY
