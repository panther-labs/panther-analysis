def rule(event):
    return (
        event.get("eventSource") == "sso.amazonaws.com" and event.get("eventName") == "CreateToken"
    )
