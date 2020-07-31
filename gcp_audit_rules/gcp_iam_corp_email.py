def rule(event):
    if event['protoPayload'].get('methodName') != 'SetIamPolicy':
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
        if delta.get('member').endswith('@gmail.com'):
            return True
    return False


def dedup(event):
    return event['resource'].get('labels', {}).get('project_id',
                                                   '<PROJECT_NOT_FOUND>')


def title(event):
    return 'A GCP IAM account has been created with a Gmail email in {}'.format(
        dedup(event))
