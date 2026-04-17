def zia_success(event):
    if (
        event.deep_get("event", "errorcode", default="") == "None"
        and event.deep_get("event", "result", default="") == "SUCCESS"
    ):
        return True
    return False


def zia_alert_context(event):
    event_data = event.get("event", {})
    return {
        "action": event_data.get("action", ""),
        "admin_id": event_data.get("adminid", ""),
        "category": event_data.get("category", ""),
        "client_ip": event_data.get("clientip", ""),
        "preaction": event_data.get("preaction", ""),
        "postaction": event_data.get("postaction", ""),
    }
