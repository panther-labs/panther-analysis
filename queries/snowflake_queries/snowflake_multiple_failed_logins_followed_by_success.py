def rule(_):
    return True

def title(event):
    return (
        f"Username [{event.get('user_name','<USER_NOT_FOUND>')}] from clientIP "
        f"[{event.get('client_ip','<CLIENT_IP_NOT_FOUND>')}] "
        f"registered [{event.get('num_fails','<NUM_FAILS_NOT_FOUND>')}] failed logins "
        f" which began at [{event.get('start_of_unsuccessful_logins_time','<UNSUCCESSFUL_LOGINS_START_TIME_NOT_FOUND>')}] "
        f"followed by a successful login which occurred at "
        f"[{event.get('successful_login_time','<SUCCESS_LOGIN_TIME_NOT_FOUND>')}]."
    )
 