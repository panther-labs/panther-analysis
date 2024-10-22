def rule(event):
    # Return true for any login attempt; Let Panther's dedup and threshold handle the brute force
    #   detection.
    return event.get("EVENT_TYPE") == "LOGIN" and event.get("IS_SUCCESS") == "NO"


def title(event):
    return (
        f"User {event.get('USER_NAME', '<UNKNOWN USER>')} has exceeded the failed logins threshold"
    )


def dedup(event):
    return event.get("USER_NAME", "<UNKNOWN USER>") + event.get(
        "REPORTED_CLIENT_TYPE", "<UNKNOWN CLIENT TYPE>"
    )
