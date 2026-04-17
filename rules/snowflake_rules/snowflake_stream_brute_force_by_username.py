def rule(event):
    # Return true for any login attempt; Let Panther's dedup and threshold handle the brute force
    #   detection.
    return (
        event.get("EVENT_TYPE") == "LOGIN"
        and event.get("IS_SUCCESS") == "NO"
        and event.get("ERROR_MESSAGE") != "OVERFLOW_FAILURE_EVENTS_ELIDED"
        # ^^ OVERFLOW_FAILURE_EVENTS_ELIDED are placeholder logs -> no point in alerting
    )


def title(event):
    return (
        f"User {event.get('USER_NAME', '<UNKNOWN USER>')} has exceeded the failed logins threshold"
    )


def severity(event):
    # If the error appears to be caused by an automation issue, downgrade to INFO
    common_errors = {"JWT_TOKEN_INVALID_PUBLIC_KEY_FINGERPRINT_MISMATCH"}
    if event.get("ERROR_MESSAGE") in common_errors:
        return "INFO"
    return "DEFAULT"


def dedup(event):
    return event.get("USER_NAME", "<UNKNOWN USER>") + event.get(
        "REPORTED_CLIENT_TYPE", "<UNKNOWN CLIENT TYPE>"
    )
