def rule(event):
    return any(keyword in event.get("Intro", "") for keyword in ["disconnected", "reconnected"])


def title(event):
    return event.get("Intro", "Canary Disconnected/Reconnected")


def severity(event):
    if "reconnected" in event.get("Intro", ""):
        return "Low"
    return "Default"
