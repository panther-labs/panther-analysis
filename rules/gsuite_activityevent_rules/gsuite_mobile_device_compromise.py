def rule(event):
    if event.deep_get("id", "applicationName") != "mobile":
        return False

    if event.get("name") == "DEVICE_COMPROMISED_EVENT":
        return bool(event.deep_get("parameters", "DEVICE_COMPROMISED_STATE") == "COMPROMISED")

    return False


def title(event):
    return (
        f"User [{event.deep_get('parameters', 'USER_EMAIL', default='<UNKNOWN_USER>')}]'s "
        f"device was compromised"
    )
