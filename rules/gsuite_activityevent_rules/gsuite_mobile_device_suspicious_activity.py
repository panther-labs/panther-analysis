def rule(event):
    if event.deep_get("id", "applicationName") != "mobile":
        return False

    return bool(event.get("name") == "SUSPICIOUS_ACTIVITY_EVENT")


def title(event):
    return (
        f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
        f"'s device was compromised"
    )
