def rule(event):
    if str(event.get("event_type_id")) == "5":
        return True
    return False


def title(event):
    return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] successfully logged in"
