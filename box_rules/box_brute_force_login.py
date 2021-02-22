from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type") == "FAILED_LOGIN"


def title(event):
    return (
        f"User [{deep_get(event, 'source', 'name', default='<UNKNOWN_USER>')}]"
        f" has exceeded the failed login threshold."
    )
