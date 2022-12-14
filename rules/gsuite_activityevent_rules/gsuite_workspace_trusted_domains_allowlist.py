from panther_base_helpers import deep_get


def rule(event):
    return event.get("type") == "DOMAIN_SETTINGS" and event.get("name", "").endswith(
        "_TRUSTED_DOMAINS"
    )


def title(event):
    return (
        f"GSuite Workspace Trusted Domains Modified "
        f"[{event.get('name', '<NO_EVENT_NAME>')}] "
        f"with [{deep_get(event, 'parameters', 'DOMAIN_NAME', default='<NO_DOMAIN_NAME>')} "
        f"performed by [{deep_get(event, 'actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )
