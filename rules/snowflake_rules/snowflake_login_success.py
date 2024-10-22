def rule(event):
    return all((event.get("EVENT_TYPE") == "LOGIN", event.get("IS_SUCCESS") == "YES"))
