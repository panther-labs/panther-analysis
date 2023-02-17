from panther_base_helpers import deep_get, pattern_match_list, aws_rule_context

events = {
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
    if event.get("errorCode"):
        return False
    # Filter: Internal AWS
    if deep_get(event, "userIdentity", "type") in ("AWSAccount", "AWSService"):
        return False
    # Filter: Non "Get" events
    if not pattern_match_list(event.get("eventName", ""), events):
        return False
    return True


def title(event):
    return (
        f"IP Address [{event.get('sourceIPAddress')}]"
        f"User [{deep_get(event, 'userIdentity', 'arn')}]"
        f"Suspicious events detected by [{deep_get(event, 'sourceIPAddress')}]"
        f"From [{deep_get(event, 'userIdentity', 'arn')}]"
    )


def alert(event):
    return aws_rule_context(event)
