from ipaddress import ip_address

from panther_base_helpers import deep_get, pattern_match_list, aws_rule_context

events = {
# Monitor for object level events
    'PutObject',
    'GetObject',
    'DeleteObject',
    'CopyObject',
    'InitiateMultipartUpload',
    'UploadPart',
    'CompleteMultipartUpload',
    'AbortMultipartUpload',
    'ListMultipartUploadParts',

# Monitor for bucket level events
# Also check ListBucket to reveal object enumeration.
    'ListBucket',
    'CreateBucket',
    'DeleteBucket',
    'PutBucketAcl',
    'PutBucketPolicy',
    'PutBucketCors',
    'PutBucketLifecycle',
    'PutBucketReplication',
    'PutBucketEncryption',
    'PutBucketTagging',

#Monitor for events associated with user creation, deletion, & modification
    'CreateUser',
    'CreateLoginProfile',
    'AddUserToGroup',
    'DeleteUser',
    'DeleteLoginProfile',
    'RemoveUserFromGroup',
    'UpdateUser',
    'UpdateLoginProfile',
    'PutUserPolicy',
    'AddUserToGroup',
    'RemoveUserFromGroup'

#Monitor actions that can execute a script
    'InvokeFunction',
    'SendCommand',
    'RunInstances',
    'SubmitJob',
    'TerminateJob',
    'StartAutomationExecution',
    'StopAutomationExecution'

}

# Some AWS IP addresses listed as 'malicious' are stale
# This enables allowing specific roles where this may occur
_ALLOWED_ROLES = {
    '*PantherAuditRole-*',
    '*PantherLogProcessingRole-*',
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
    if pattern_match_list(deep_get(event, "userIdentity", "arn", default=""), _ALLOWED_ROLES):
        return False
    # Filter: Non "Get" events
    if not pattern_match_list(event.get("eventName", ""), events):
        return False
    return True


def title(event):
    # Group by ip-arn combinations
    ip = deep_get(event, "sourceIPAddress")
    arn = deep_get(event, "userIdentity", "arn")
    return f"Suspicious reconnaissance events detected by {ip} from {arn}"

def alert(event):
    return aws_rule_context(event)
