def rule(event):
    # filter events; event type 90 is an unauthorized application access event id
    return str(event.get("event_type_id")) == "90"


def generate_alert_title(event):
    return (
        f"OneLogin Alert: User [{event.get('user_name', '<UNKNOWN_USER>')}] exceeded "
        f"unauthorized application access threshold"
    )
