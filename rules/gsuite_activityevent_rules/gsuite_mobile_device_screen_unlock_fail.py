from panther_base_helpers import deep_get

MAX_UNLOCK_ATTEMPTS = 10


def rule(event):
    if deep_get(event, "id", "applicationName") != "mobile":
        return False

    if event.get("name") == "FAILED_PASSWORD_ATTEMPTS_EVENT":
        attempts = deep_get(event, "parameters", "FAILED_PASSWD_ATTEMPTS")
        return int(attempts if attempts else 0) > MAX_UNLOCK_ATTEMPTS

    return False


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
        f"'s device had multiple failed unlock attempts"
    )
