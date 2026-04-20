def rule(event):
    return (
        event.get("EVENT_TYPE") == "LOGIN"
        and event.get("IS_SUCCESS") == "NO"
        and event.get("ERROR_MESSAGE") != "OVERFLOW_FAILURE_EVENTS_ELIDED"
    )


def unique(event):
    return event.get("USER_NAME", "UNKNOWN_USER")


def dedup(event):
    return event.get("CLIENT_IP", "UNKNOWN_IP")


def title(event):
    client_ip = event.get("CLIENT_IP", "UNKNOWN_IP")
    return f"[Snowflake] Password spray detected from IP [{client_ip}] targeting multiple accounts"


def severity(event):
    # Downgrade JWT key mismatches to INFO as these are typically automation misconfiguration
    if event.get("ERROR_MESSAGE") == "JWT_TOKEN_INVALID_PUBLIC_KEY_FINGERPRINT_MISMATCH":
        return "INFO"
    return "DEFAULT"


def alert_context(event):
    return {
        "client_ip": event.get("CLIENT_IP", "UNKNOWN_IP"),
        "user_name": event.get("USER_NAME", "UNKNOWN_USER"),
        "client_type": event.get("REPORTED_CLIENT_TYPE"),
        "error_code": event.get("ERROR_CODE"),
        "error_message": event.get("ERROR_MESSAGE"),
    }
