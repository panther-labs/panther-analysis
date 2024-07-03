def rule(event):
    # Return True to match the log event and trigger an alert.
    return event.get("eventSource") == "sso.amazonaws.com" and event.get("eventName") == "ListApplications"
