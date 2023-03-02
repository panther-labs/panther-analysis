from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

# API calls that are indicative of IAM Policy changes
POLICY_CHANGE_EVENTS = {
    "DeleteGroupPolicy",
    "DeleteRolePolicy",
    "DeleteUserPolicy",
    # Put<Entity>Policy is for inline policies.
    # these can be moved into their own rule if inline policies are of a greater concern.
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "CreatePolicy",
    "DeletePolicy",
    "CreatePolicyVersion",
    "DeletePolicyVersion",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in POLICY_CHANGE_EVENTS


def dedup(event):
    return event.get("recipientAccountId")


def alert_context(event):
    return aws_rule_context(event)
