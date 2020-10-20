def rule(event):
    return (
        event.get('event_type') == 'CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION' or
        event.get('event_type') == 'CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION')


def title(event):
    return 'User [{}] violated a content workflow policy.'.format(
        event.get('created_by', {}).get('name', "<UNKNOWN_USER>"))
