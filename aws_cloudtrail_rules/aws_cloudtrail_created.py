from panther_base_helpers import deep_get

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CREATE_UPDATE = {
    "CreateTrail",
    "UpdateTrail",
    "StartLogging",
}


def rule(event):
    return event.get("eventName") in CLOUDTRAIL_CREATE_UPDATE


def title(event):
    return f"CloudTrail [{deep_get(event, 'requestParameters', 'name')}] was created/updated"
