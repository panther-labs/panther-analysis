def rule(event):
    # DEVICE_TRUST_CHECK_FAILED
    #  detect when a user attempts to login from an untrusted device
    return event.get("event_type") == "DEVICE_TRUST_CHECK_FAILED"


def title(event):
    return (
        f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] "
        f"attempted to login from an untrusted device."
    )
