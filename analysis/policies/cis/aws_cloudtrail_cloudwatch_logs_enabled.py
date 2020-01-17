import datetime

MAX_TIME_BETWEEN_LOGS = datetime.timedelta(hours=24)
AWS_TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def policy(resource):
    # Check if a CloudWatch Logs Group has been set, and received at least one log
    if not (
        resource['CloudWatchLogsLogGroupArn'] and
        resource['Status']['LatestCloudWatchLogsDeliveryTime']
    ):
        return False

    # Check if the last log sent is within the allowable timeframe
    last_log_time = datetime.datetime.strptime(
        resource['Status']['LatestCloudWatchLogsDeliveryTime'], AWS_TIMESTAMP_FORMAT
    )
    return (datetime.datetime.utcnow() - last_log_time) <= MAX_TIME_BETWEEN_LOGS
