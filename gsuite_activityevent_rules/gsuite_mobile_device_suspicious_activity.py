from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "mobile":
        return False

    return bool(event.get("name") == "SUSPICIOUS_ACTIVITY_EVENT")


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
        f"'s device was compromised"
    )
