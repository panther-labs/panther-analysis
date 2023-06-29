from panther_base_helpers import deep_get


def rule(event):
    # Nick was here
    return event.get("event_type") == "ACCESS_GRANTED"


def title(event):
    return (
        f"User [{deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>')}] granted "
        f"access to their account"
    )
