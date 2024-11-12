def rule(_):
    return True


def title(event):
    username = event.get("user_name", "<UNKNOWN USER>")
    source = event.get("p_source_label", "<UNKNOWN SOURCE>")
    return f"{source}: Abnormally large query volume from user {username}"
