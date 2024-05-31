def rule(_):
    return True


def title(event):
    auth_method = event.get("authentication_method", "<NO AUTHENTICATION METHOD FOUND>")
    logon_id = event.get("login_event_id", "<NO LOGIN EVENT ID FOUND>")
    session_id = event.get("session_id", "<NO SESSION ID FOUND>")
    user_name = event.get("user_name", "<NO USER NAME FOUND>")
    return f"{user_name} accessed Snowflake with login event ID {logon_id} and session ID {session_id} via {auth_method}"
