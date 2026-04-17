def wiz_success(event):
    if event.get("status", "") == "SUCCESS":
        return True
    return False


def wiz_alert_context(event):
    return {
        "action": event.get("action", ""),
        "actor": wiz_actor(event),
        "source_ip": event.get("sourceip", ""),
        "event_id": event.get("id", ""),
        "action_parameters": event.get("actionparameters", ""),
    }


def wiz_actor(event):
    user = event.get("user")
    serviceaccount = event.get("serviceAccount")

    if user is not None:
        return {
            "type": "user",
            "id": user.get("id"),
            "name": user.get("name"),
        }

    if serviceaccount is not None:
        return {
            "type": "serviceaccount",
            "id": serviceaccount.get("id"),
            "name": serviceaccount.get("name"),
        }

    return {
        "type": "unknown",
        "id": "<Unknown ID>",
        "name": "<Unknown Name>",
    }
