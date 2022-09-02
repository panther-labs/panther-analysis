def rule(event):
    return (
        event.get("actionName") == "UPDATE_SAML_SETTINGS"
        and event.get("actionResult") == "SUCCEEDED"
    )


def title(event):
    return f"Panther SAML config has been modifed by {event.udm('actor_user')}"


def alert_context(event):
    return {
        "user": event.udm("actor_user"),
        "ip": event.udm("source_ip"),
    }
