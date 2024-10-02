MAX_UNLOCK_ATTEMPTS = 10


def rule(event):
    if event.deep_get("id", "applicationName") != "mobile":
        return False

    if event.get("name") == "FAILED_PASSWORD_ATTEMPTS_EVENT":
        attempts = event.deep_get("parameters", "FAILED_PASSWD_ATTEMPTS")
        return int(attempts if attempts else 0) > MAX_UNLOCK_ATTEMPTS

    return False


def title(event):
    return (
        f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
        f"'s device had multiple failed unlock attempts"
    )
