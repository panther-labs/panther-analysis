from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get, aws_rule_context

EVENTS = {
    # Monitor for object level events
    "PutObject",
    "GetObject",
    "DeleteObject",
    "CopyObject",
    "InitiateMultipartUpload",
    "UploadPart",
    "CompleteMultipartUpload",
    "AbortMultipartUpload",
    "ListMultipartUploadParts",
    # Monitor for bucket level events
    # Also check ListBucket to reveal object enumeration.
    "ListBucket",
    "CreateBucket",
    "DeleteBucket",
    "PutBucketAcl",
    "PutBucketPolicy",
    "PutBucketCors",
    "PutBucketLifecycle",
    # Monitor actions that can execute a script
    "RunInstances",
    "SubmitJob",
    "TerminateJob",
    "StartAutomationExecution",
    "StopAutomationExecution",
}


def rule(event):
    # Filter: Non-S3 events
    if event.get("eventSource") != "s3.amazonaws.com":
        return False
    # Filter: Errors
    if not aws_cloudtrail_success(event):
        return False
    # Filter: Internal AWS
    if deep_get(event, "userIdentity", "type") in ("AWSAccount", "AWSService"):
        return False
    # Filter: Non "Get" events
    return event.get("eventName", "") in EVENTS


def title(event):
    return (
        f"AWS Identity [{deep_get(event, 'userIdentity', 'arn')}] "
        f"executed possible reconnaissance command [event.get('eventName', '')] "
        f"in AWS Account [event.get('recipientAccountId', '')]"
    )


def alert(event):
    return aws_rule_context(event)
