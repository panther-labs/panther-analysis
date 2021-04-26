def rule(event):  # pylint: disable=unused-argument
    return True

def title(event):
    return f"Login attempts from IP [{event.get('client_ip','<UNKNOWN_USER>')}] has exceeded the failed logins threshold"
