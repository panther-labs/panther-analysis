def rule(event):
    return event.get("EVENT_TYPE", "<NO_EVENT_TYPE_FOUND>") == "LoginAs"


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will act as deduplication string.
    admin = event.get("DELEGATED_USER_NAME", "<NO_ADMIN_FOUND>")
    user_id = event.get("USER_ID", "<NO_USER_ID_FOUND>")
    return f"Salesforce admin [{admin}] logged in as a regular user with the user id [{user_id}]."
