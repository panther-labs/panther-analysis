def slack_alert_context(event):
    return {
        "actor-name": event.deep_get("actor", "user", "name", default="<MISSING_NAME>"),
        "actor-email": event.deep_get("actor", "user", "email", default="<MISSING_EMAIL>"),
        "actor-ip": event.deep_get("context", "ip_address", default="<MISSING_IP>"),
        "user-agent": event.deep_get("context", "ua", default="<MISSING_UA>"),
    }
