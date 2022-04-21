from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "mobile":
        return False

    if event.get("name") == "DEVICE_COMPROMISED_EVENT":
        return bool(deep_get(event, "parameters", "DEVICE_COMPROMISED_STATE") == "COMPROMISED")

    return False


def title(event):
    return (
        f"User [{deep_get(event, 'parameters', 'USER_EMAIL', default='<UNKNOWN_USER>')}]'s "
        f"device was compromised"
    )
