from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

# API calls that are indicative of KMS CMK Deletion
KMS_LOSS_EVENTS = {"DisableKey", "ScheduleKeyDeletion"}
KMS_KEY_TYPE = "AWS::KMS::Key"


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in KMS_LOSS_EVENTS


def dedup(event):
    for resource in event.get("resources") or []:
        if resource.get("type", "") == KMS_KEY_TYPE:
            return resource.get("ARN")
    return event.get("eventName")


def alert_context(event):
    return aws_rule_context(event)
