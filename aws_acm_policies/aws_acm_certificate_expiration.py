import datetime

AWS_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
EXPIRATION_BUFFER = datetime.timedelta(days=60)


def policy(resource):
    if not resource.get("NotAfter"):
        return False
    time_to_expiration = (
        datetime.datetime.strptime(resource["NotAfter"], AWS_TIMESTAMP_FORMAT)
        - datetime.datetime.now()
    )

    return time_to_expiration >= EXPIRATION_BUFFER
