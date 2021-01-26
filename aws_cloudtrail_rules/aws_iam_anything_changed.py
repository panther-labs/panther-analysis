IAM_CHANGE_ACTIONS = [
    'Add',
    'Attach',
    'Change',
    'Create',
    'Deactivate',
    'Delete',
    'Detach',
    'Enable',
    'Put',
    'Remove',
    'Set',
    'Update',
    'Upload',
]


def rule(event):
    # Only check IAM events, as the next check is relatively computationally
    # expensive and can often be skipped
    if event.get('eventSource') != 'iam.amazonaws.com':
        return False

    return any([
        event.get('eventName', '').startswith(action) for action in IAM_CHANGE_ACTIONS
    ])
