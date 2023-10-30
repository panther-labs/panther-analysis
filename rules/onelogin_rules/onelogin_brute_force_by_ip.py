def rule(event):
    # filter events; event type 6 is a failed authentication
    return str(event.get("event_type_id")) == "6"


def title(event):
    return f"IP [{event.get('ipaddr', '<UNKNOWN_IP>')}] has exceeded the failed logins threshold"
