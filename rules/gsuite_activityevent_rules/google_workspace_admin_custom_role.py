def rule(event):
    # Return True to match the log event and trigger an alert.
    # Create Alert if there is a custom role created under delegated admin settings
    return (
        event.get("type", "") == "DELEGATED_ADMIN_SETTINGS"
        and event.get("name", "") == "CREATE_ROLE"
    )


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method
    # will act as deduplication string.
    return (
        f"Google Workspace Administrator "
        f"[{event.get('actor',{}).get('email','NO_EMAIL_FOUND')}] "
        f"created a new admin role "
        f"[{event.get('parameters',{}).get('ROLE_NAME','NO_ROLE_NAME_FOUND')}]."
    )
