def rule(event):
    # Return True to match the log event and trigger an alert.
    return (
        event.get("name") == "ADD_APPLICATION"
        and event.get("parameters", {}).get("APPLICATION_ENABLED", "<NO_APPLICATION_FOUND>")
        == "true"
    )


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method
    # will act as deduplication string.
    return (
        f"Google Workspace User [{event.get('actor',{}).get('email','<NO_EMAIL_PROVIDED>')}] "
        f"enabled a new Google Workspace Marketplace application "
        f"[{event.get('parameters',{}).get('APPLICATION_NAME','<NO_APPLICATION_NAME_FOUND>')}]"
    )
