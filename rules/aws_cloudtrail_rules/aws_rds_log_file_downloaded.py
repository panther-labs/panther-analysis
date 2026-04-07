from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    if event.get("eventName") != "DownloadDBLogFilePortion":
        return False
    return event.deep_get("errorCode") is None


def title(event):
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier", default="<UNKNOWN>")
    log_file = event.deep_get("requestParameters", "logFileName", default="<UNKNOWN_FILE>")
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    return f"RDS Log Downloaded: [{log_file}] from [{db_identifier}] by [{user}]"


def dedup(event):
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier", default="unknown")
    log_file = event.deep_get("requestParameters", "logFileName", default="unknown")
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{db_identifier}:{log_file}"


def alert_context(event):
    context = aws_rds_context(event)
    context["log_file_name"] = event.deep_get("requestParameters", "logFileName", default="N/A")
    context["marker"] = event.deep_get("requestParameters", "marker", default="N/A")
    context["number_of_lines"] = event.deep_get("requestParameters", "numberOfLines", default="N/A")
    return context
