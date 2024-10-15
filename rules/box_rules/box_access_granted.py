def rule(event):
    return event.get("event_type") == "ACCESS_GRANTED"


def title(event):
    return (
        f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] granted "
        f"access to their account"
    )
