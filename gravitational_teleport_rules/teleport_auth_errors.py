def rule(event):
    return bool(event.get("error")) and event.get("event") == "auth"


def title(event):
    return f"A high volume of SSH errors was detected from user [{event.get('user', '<UNKNOWN_USER>')}]"
