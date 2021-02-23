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
    return event.get("eventName") in POLICY_CHANGE_EVENTS


def dedup(event):
    return event.get("recipientAccountId")
