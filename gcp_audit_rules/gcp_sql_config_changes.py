def rule(event):
    return event['protoPayload'].get(
        'methodName') == 'cloudsql.instances.update'


def dedup(event):
    return event['resource'].get('labels', {}).get('project_id',
                                                   '<PROJECT_NOT_FOUND>')
