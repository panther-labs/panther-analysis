def rule(event):
    return (event['resource'].get('type') == 'gcs_bucket' and
            event['protoPayload'].get('methodName')
            == 'storage.setIamPermissions')


def dedup(event):
    return event['resource'].get('labels', {}).get('project_id',
                                                   '<PROJECT_NOT_FOUND>')
