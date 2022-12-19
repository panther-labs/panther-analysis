def rule(event):
    # Return True to match the log event and trigger an alert.
    return event.get("action", "") == "admin_lockout"


def title(event):
    # If no 'dedup' function is defined, the return value
    # of this method will act as deduplication string.
    return (
        f"Duo User [{event.get('username', '<NO_USER_FOUND>')}] is "
        f"temporarily locked out due to too many passcode attempts."
    )
