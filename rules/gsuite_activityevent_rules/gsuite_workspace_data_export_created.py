def rule(event):
    return event.get("name", "").startswith("CUSTOMER_TAKEOUT_")


def title(event):
    return (
        f"GSuite Workspace Data Export "
        f"[{event.get('name', '<NO_EVENT_NAME>')}] "
        f"performed by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )
