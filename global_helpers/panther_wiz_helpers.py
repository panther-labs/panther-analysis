def wiz_success(event):
    if event.get("status", "") == "SUCCESS":
        return True
    return False


def wiz_alert_context(event):
    return {
        "action": event.get("action", ""),
        "user": event.get("user", ""),
        "source_ip": event.get("sourceip", ""),
        "event_id": event.get("id", ""),
        "service_account": event.get("serviceaccount", ""),
        "action_parameters": event.get("actionparameters", ""),
    }
