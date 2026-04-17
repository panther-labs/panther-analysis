def rule(_):
    return True


def title(event):
    user = event.get("user", "<NO_USER_FOUND>")
    return f"Notion User [{user}] deleted multiple pages."
