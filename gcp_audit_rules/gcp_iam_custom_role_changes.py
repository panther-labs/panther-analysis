ROLE_METHODS = {
    'google.iam.admin.v1.CreateRole', 'google.iam.admin.v1.DeleteRole',
    'google.iam.admin.v1.UpdateRole'
}


def rule(event):
    return (event['resource'].get('type') == 'iam_role' and
            event['protoPayload'].get('methodName') in ROLE_METHODS)


def dedup(event):
    return event['resource'].get('labels', {}).get('project_id',
                                                   '<PROJECT_NOT_FOUND>')
