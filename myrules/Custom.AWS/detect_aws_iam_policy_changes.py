# Detection: Detect IAM Policy Changes in AWS CloudTrail
# Description: This detection triggers when an IAM policy is created, updated, or deleted in AWS.


def rule(event):

    monitored_actions = [
        "CreatePolicy",
        "DeletePolicy",
        "CreatePolicyVersion",
        "DeletePolicyVersion",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "AttachUserPolicy",
        "DetachUserPolicy",
    ]

    return (
        event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") in monitored_actions
    )


def title(event):
    return f"IAM Policy Change Detected: {event.get('eventName')}"


def dedup(event):
    return f"{event.get('eventSource')}-{event.get('eventName')}-{event.get('eventTime')}"


def severity(event):
    # Default to medium severity, adjust based on event name if needed
    high_severity_actions = ["DeletePolicy", "DeletePolicyVersion"]
    if event.get("eventName") in high_severity_actions:
        return 5
    return 3
