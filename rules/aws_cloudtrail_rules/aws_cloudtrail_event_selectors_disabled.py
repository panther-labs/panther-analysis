from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_EDIT_SELECTORS = {"PutEventSelectors"}


def rule(event):
    if not (aws_cloudtrail_success(event) and event.get("eventName") in CLOUDTRAIL_EDIT_SELECTORS):
        return False

    # Check if management events are included for each selector.
    #    deep_walk only returns a list if there's more than 1 entry in the nested array, so we must
    #    enforce it to be a list.
    includes = event.deep_walk("requestParameters", "eventSelectors", "includeManagementEvents")

    if includes is None:
        includes = []

    if not isinstance(includes, list):
        includes = [includes]

    # Return False all the management events are included, else return True and raise alert
    return not all(includes)


def dedup(event):
    # Merge on the CloudTrail ARN
    return event.deep_get("requestParameters", "trailName", default="<UNKNOWN_NAME>")


def title(event):
    return (
        f"Management events have been exluded from CloudTrail [{dedup(event)}] in account "
        f"[{event.get('recipientAccountId')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
