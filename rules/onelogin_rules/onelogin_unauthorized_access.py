def rule(event):
    # filter events; event type 90 is an unauthorized application access event id
    return event.get("event_type_id") == 90


def title(event):
    return (
        f"User [{event.get('user_name', '<UNKNOWN_USER>')}] has exceeded the unauthorized "
        f"application access attempt threshold"
    )
