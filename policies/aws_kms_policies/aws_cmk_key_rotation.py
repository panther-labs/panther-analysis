def policy(resource):
    # per AWS Docs automatic rotation is only supported on managed symmetric keys
    # These are of Origin AWS_KMS
    if resource.get("Origin") != "AWS_KMS":
        return True
    return (  # Ignore AWS managed keys
        resource.get("KeyManager") != "CUSTOMER"  # Check that the KeyRotation exists
        # Explicit True check to avoid returning NoneType
        or (resource.get("KeyRotationEnabled") is True and resource.get("KeyState") == "Enabled")
    )


def dedup(resource):
    return f"AWS KMS CMK Key Rotation - Account {resource.get('AccountId')}"
