from panther_gsuite_helpers import gsuite_activityevent_alert_context


def rule(event):
    return event.get("name", "").startswith("CUSTOMER_TAKEOUT_")


def title(event):
    return (
        f"GSuite Workspace Data Export "
        f"[{event.get('name', '<NO_EVENT_NAME>')}] "
        f"performed by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )


def alert_context(event):
    return gsuite_activityevent_alert_context(event)
