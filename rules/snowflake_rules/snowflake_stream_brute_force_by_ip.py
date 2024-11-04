def rule(event):
    # Return true for any login attempt; Let Panther's dedup and threshold handle the brute force
    #   detection.
    return event.get("EVENT_TYPE") == "LOGIN" and event.get("IS_SUCCESS") == "NO"


def title(event):
    return (
        "Login attempts from IP "
        f"{event.get('CLIENT_IP', '<UNKNOWN IP>')} "
        "have exceeded the failed logins threshold"
    )


def dedup(event):
    return event.get("CLIENT_IP", "<UNKNOWN IP>") + event.get(
        "REPORTED_CLIENT_TYPE", "<UNKNOWN CLIENT TYPE>"
    )
