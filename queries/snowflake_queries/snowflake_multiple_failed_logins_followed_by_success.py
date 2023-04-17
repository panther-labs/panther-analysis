def rule(_):
    return True

def title(event):
    return (
        f"Username [{event.get('user_name','<USER_NOT_FOUND>')}] from clientIP "
        f"[{event.get('client_ip','<CLIENT_IP_NOT_FOUND>')}]] "
        f"registered multiple failed logins followed by a success."
    )
 