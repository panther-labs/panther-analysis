def rule(_):
    return True


def title(event):
    return (
        f"Snowflake: {event.get('counts_by_user', 'many')} failed login attempts by user "
        f"[{event.get('user_name','<UNKNOWN_USER>')}]"
    )


def severity(event):
    # If the error appears to be caused by an automation issue, downgrade to INFO
    common_errors = {"JWT_TOKEN_INVALID_PUBLIC_KEY_FINGERPRINT_MISMATCH"}
    if event.get("ERROR_MESSAGE") in common_errors:
        return "INFO"
    return "DEFAULT"


def dedup(event):
    # Dedup on title and severity
    return f"[{severity(event)}] {title(event)}"
