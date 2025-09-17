def rule(event):
    # filter events; event type 17 is a user deleted
    return str(event.get("event_type_id")) == "17"


def generate_alert_title(event):
    return (
        f"OneLogin Alert: User [{event.get('actor_user_name', '<UNKNOWN_USER>')}] "
        f"exceeded account deletion threshold"
    )
