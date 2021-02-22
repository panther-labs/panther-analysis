from panther_base_helpers import deep_get

POLICY_VIOLATIONS = {
    "CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION",
    "CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION",
}


def rule(event):
    return event.get("event_type") in POLICY_VIOLATIONS


def title(event):
    return "User [{}] violated a content workflow policy.".format(
        deep_get(event, "created_by", "name", default="<UNKNOWN_USER>")
    )
