def is_valid_arn(arn, service):
    if service == "logs":
        return arn.startswith("arn:aws:logs:") and ":log-group:" in arn
    if service == "s3":
        return arn.startswith("arn:aws:s3:::") and len(arn.split(":")) == 6
    if service == "firehose":
        return arn.startswith("arn:aws:firehose:") and ":deliverystream/" in arn
    return False


def policy(resource):
    # Check if WAF logging configuration exists
    logging_config = resource.get("LoggingConfiguration")
    if not logging_config:
        return False

    # Get the logging destinations
    destinations = logging_config.get("LogDestinationConfigs", [])

    # Validate the ARNs for CloudWatch Logs, S3, or Kinesis Firehose
    for destination in destinations:
        if (
            is_valid_arn(destination, "logs")
            or is_valid_arn(destination, "s3")
            or is_valid_arn(destination, "firehose")
        ):
            return True

    return False
