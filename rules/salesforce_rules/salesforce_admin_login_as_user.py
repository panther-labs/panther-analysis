def rule(event):
    return event.get("EVENT_TYPE", "<NO_EVENT_TYPE_FOUND>") == "LoginAs"


def title(event):
    admin = event.get("DELEGATED_USER_NAME", "<NO_ADMIN_FOUND>")
    user_id = event.get("USER_ID", "<NO_USER_ID_FOUND>")
    return f"Salesforce admin [{admin}] logged in as a regular user with the user id [{user_id}]."
