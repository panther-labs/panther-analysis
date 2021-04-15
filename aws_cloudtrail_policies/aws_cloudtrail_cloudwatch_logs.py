import datetime

from panther_base_helpers import deep_get
from panther_oss_helpers import resolve_timestamp_string

MAX_TIME_BETWEEN_LOGS = datetime.timedelta(hours=24)


def policy(resource):
    # Check if a CloudWatch Logs Group has been set, and received at least one log
    if not (
        resource.get("CloudWatchLogsLogGroupArn")
        and deep_get(resource, "Status", "LatestCloudWatchLogsDeliveryTime")
    ):
        return False

    # Check if the last log sent is within the allowable timeframe
    last_log_time = resolve_timestamp_string(deep_get(resource, "Status", "LatestCloudWatchLogsDeliveryTime"))

    if not last_log_time:
        return True
    return (datetime.datetime.utcnow() - last_log_time) <= MAX_TIME_BETWEEN_LOGS
