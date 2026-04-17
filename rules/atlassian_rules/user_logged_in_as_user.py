def rule(event):
    return (
        event.deep_get("attributes", "action", default="<unknown-action>")
        == "user_logged_in_as_user"
    )


def title(event):
    actor = event.deep_get("attributes", "actor", "email", default="<unknown-email>")
    context = event.deep_get("attributes", "context", default=[{}])
    impersonated_user = context[0].get("attributes", {}).get("email", "<unknown-email>")
    return f"{actor} logged in as {impersonated_user}."


def alert_context(event):
    return {
        "Timestamp": event.deep_get("attributes", "time", default="<unknown-time>"),
        "Actor": event.deep_get("attributes", "actor", "email", default="<unknown-actor-email>"),
        "Impersonated user": event.deep_get("attributes", "context", default=[{}])[0]
        .get("attributes", {})
        .get("email", "<unknown-email>"),
        "Event ID": event.get("id"),
    }
