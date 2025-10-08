from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    return event.get("type") == "DOMAIN_SETTINGS" and event.get("name", "").endswith(
        "_TRUSTED_DOMAINS"
    )


def title(event):
    return (
        f"GSuite Workspace Trusted Domains Modified "
        f"[{event.get('name', '<NO_EVENT_NAME>')}] "
        f"with [{event.deep_get('parameters', 'DOMAIN_NAME', default='<NO_DOMAIN_NAME>')}] "
        f"performed by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
