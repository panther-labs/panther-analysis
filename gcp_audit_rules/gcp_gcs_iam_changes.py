from panther_base_helpers import deep_get


def rule(event):
    return (
        deep_get(event, 'resource', 'type') == 'gcs_bucket'
        and deep_get(event, 'protoPayload', 'methodName') == 'storage.setIamPermissions'
    )


def dedup(event):
    return deep_get(event, 'resource', 'labels', 'project_id', default='<UNKNOWN_PROJECT>')
