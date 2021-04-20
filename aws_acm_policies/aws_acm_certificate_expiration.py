import datetime
from panther_oss_helpers import resolve_timestamp_string


AWS_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
EXPIRATION_BUFFER = datetime.timedelta(days=60)


def policy(resource):
    if not resource.get("NotAfter"):
        return False

    timestamp = resolve_timestamp_string(resource.get("NotAfter"))

    if not timestamp:
        return True

    time_to_expiration = timestamp - datetime.datetime.now()

    return time_to_expiration >= EXPIRATION_BUFFER
