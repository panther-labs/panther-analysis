POLICY_VIOLATIONS = {
    "CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION",
    "CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION",
}


def rule(event):
    return event.get("event_type") in POLICY_VIOLATIONS


def title(event):
    return (
        f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] "
        f"violated a content workflow policy."
    )
