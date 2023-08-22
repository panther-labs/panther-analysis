def rule(event):

    # check risk associated with this event
    if event.get("risk_score", 0) > 50:
        # a failed authentication attempt with high risk
        return str(event.get("event_type_id")) == "6"
    return False


def title(event):
    return f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] failed a high risk login attempt"
