def rule(_):
    return True


def title(event):
    return f"User [{event.get('user_name','<UNKNOWN_USER>')}] has exceeded the failed logins threshold"
 
