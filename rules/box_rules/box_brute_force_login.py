def rule(event):
    return event.get("event_type") == "FAILED_LOGIN"


def title(event):
    return (
        f"User [{event.deep_get('source', 'name', default='<UNKNOWN_USER>')}]"
        f" has exceeded the failed login threshold."
    )
