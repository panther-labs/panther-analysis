def rule(event):
    # check that this is a password change event;
    # event id 11 is actor_user changed password for user
    # Normally, admin's may change a user's password (event id 211)
    return str(event.get("event_type_id")) == "11"


def generate_alert_title(event):
    return (
        f"OneLogin Alert: Password changed for user [{event.get('user_name', '<UNKNOWN_USER>')}] "
        f"by [{event.get('actor_user_name', '<UNKNOWN_USER>')}]"
    )
