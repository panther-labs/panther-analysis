def rule(_):
    return True

def title(event):
    return f"Login attempts from IP [{event.get('client_ip','<UNKNOWN_USER>')}] have exceeded the failed logins threshold"
