from panther_base_helpers import deep_get


def rule(event):
    return (
        deep_get(event, "attributes", "action", default="<unknown-action>")
        == "user_logged_in_as_user"
    )


def title(event):
    actor = deep_get(event, "attributes", "actor", "email", default="<unknown-email>")
    impersonated_user = deep_get(
        event, "attributes", "context", default="<unknown-user-attributes>"
    )[0]["attributes"].get("email")
    return f"{actor} logged in as {impersonated_user}."


def alert_context(event):
    return {
        "Timestamp": deep_get(event, "attributes", "time", default="<unknown-time>"),
        "Actor": deep_get(event, "attributes", "actor", "email", default="<unknown-actor-email>"),
        "Impersonated user": deep_get(
            event, "attributes", "context", default="<unknown-user-attributes>"
        )[0]["attributes"].get("email"),
        "Event ID": event.get("id"),
    }
