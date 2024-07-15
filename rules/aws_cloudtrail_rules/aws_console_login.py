def rule(event):
    return event.get("eventName") == "ConsoleLogin"
