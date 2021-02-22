from panther_base_helpers import deep_get


def rule(event):
    # DEVICE_TRUST_CHECK_FAILED
    #  detect when a user attempts to login from an untrusted device
    return event.get("event_type") == "DEVICE_TRUST_CHECK_FAILED"


def title(event):
    return (
        f"User [{deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>')}] "
        f"attempted to login from an untrusted device."
    )
