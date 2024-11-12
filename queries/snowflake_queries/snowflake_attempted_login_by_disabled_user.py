def rule(_):
    return True


def title(event):
    source = event.get("p_source_label", "<UNKNOWN SOURCE>")
    username = event.get("USER_NAME", "<UNKNOWN USER>")
    return f"{source}: Attempted signin by disabled user {username}"


def alert_context(event):
    return event.get("user")
