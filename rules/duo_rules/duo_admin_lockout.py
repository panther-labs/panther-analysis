import json


def rule(event):
    # Return True to match the log event and trigger an alert.
    return event.get("action", "") == "admin_lockout"


def title(event):
    # If no 'dedup' function is defined, the return value
    # of this method will act as deduplication string.
    try:
        desc = json.loads(event.get("description", {}))
        message = desc.get("message", "<NO_MESSAGE_FOUND>")
    except ValueError:
        message = "Invalid Json"
    return (
        f"Duo Admin [{event.get('username', '<NO_USER_FOUND>')}] is "
        f"locked out. Reason: [{message}]."
    )
