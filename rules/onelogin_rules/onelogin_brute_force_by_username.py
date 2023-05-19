def rule(event):
    # filter events; event type 6 is a failed authentication
    return event.get("event_type_id") == 6


def title(event):
    return (
        f"User [{event.get('user_name', '<UNKNOWN_USER>')}] "
        f"has exceeded the failed logins threshold"
    )
