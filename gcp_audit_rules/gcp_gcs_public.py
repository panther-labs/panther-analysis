GCS_READ_ROLES = {
    'roles/storage.objectAdmin', 'roles/storage.objectViewer',
    'roles/storage.admin'
}
GLOBAL_USERS = {'allUsers', 'allAuthenticatedUsers'}


def rule(event):
    if event['protoPayload'].get('methodName') != 'storage.setIamPermissions':
        return False

    service_data = event['protoPayload'].get('serviceData')
    if not service_data:
        return False

    # Reference: bit.ly/2WsJdZS
    binding_deltas = service_data.get('policyDelta', {}).get('bindingDeltas')
    if not binding_deltas:
        return False

    for delta in binding_deltas:
        if delta['action'] != 'ADD':
            continue
        if delta.get('member') in GLOBAL_USERS and delta.get(
                'role') in GCS_READ_ROLES:
            return True
    return False


def title(event):
    return 'GCS bucket [{}] made public'.format(event['resource'].get(
        'labels', {}).get('bucket_name', '<BUCKET_NOT_FOUND>'))
