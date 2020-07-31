def get_binding_deltas(event):
    if event['protoPayload'].get('methodName') != 'SetIamPolicy':
        return []

    service_data = event['protoPayload'].get('serviceData')
    if not service_data:
        return []

    # Reference: bit.ly/2WsJdZS
    binding_deltas = service_data.get('policyDelta', {}).get('bindingDeltas')
    if not binding_deltas:
        return []
    return binding_deltas
