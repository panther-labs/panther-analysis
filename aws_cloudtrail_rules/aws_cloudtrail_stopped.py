from panther import lookup_aws_account_name
from panther_base_helpers import deep_get


# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    "DeleteTrail",
    "StopLogging",
}


def rule(event):
    return event.get("eventName") in CLOUDTRAIL_STOP_DELETE


def dedup(event):
    # Merge on the CloudTrail ARN
    return deep_get(event, "requestParameters", "name", default="<UNKNOWN_NAME>")


def title(event):
    return "CloudTrail [{}] in account [{}] was stopped/deleted".format(
        dedup(event), lookup_aws_account_name(event.get("recipientAccountId"))
    )
