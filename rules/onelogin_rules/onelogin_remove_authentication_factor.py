def rule(event):
    # verify this is a auth factor being removed
    # event id 24 is otp device deregistration
    # event id 172 is a user deleted an authentication factor
    return str(event.get("event_type_id")) == "24" or str(event.get("event_type_id")) == "172"


def dedup(event):
    return event.get("user_name", "<UNKNOWN_USER>")


def title(event):
    if str(event.get("event_type_id")) == "172":
        return (
            f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] removed an authentication "
            f"factor [{event.get('authentication_factor_description', '<UNKNOWN_AUTH_FACTOR>')}]"
        )
    return (
        f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] deactivated an otp device "
        f"[{event.get('otp_device_name', '<UNKNOWN_OTP_DEVICE>'),}]"
    )
