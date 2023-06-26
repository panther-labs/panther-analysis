def rule(_):
    return True


def title(event):
    return (
        "Login attempts from IP "
        f"[{event.get('client_ip','<UNKNOWN_USER>')}] "
        "have exceeded the failed logins threshold"
    )
