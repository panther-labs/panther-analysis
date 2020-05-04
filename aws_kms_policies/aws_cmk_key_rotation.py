def policy(resource):
    return (
        # Ignore AWS managed keys
        resource['KeyManager'] != 'CUSTOMER'
        # Check that the KeyRotation exists
        # Explicit True check to avoid returning NoneType
        or (resource['KeyRotationEnabled'] is True and
            resource['KeyState'] == 'Enabled'))
