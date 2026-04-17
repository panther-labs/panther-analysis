from panther_wiz_helpers import wiz_actor, wiz_alert_context, wiz_success


def rule(event):
    if not wiz_success(event):
        return False
    return event.get("action", "ACTION_NOT_FOUND") == "RevokeUserSessions"


def title(event):
    actor = wiz_actor(event)

    return (
        f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action "
        f"performed by {actor.get('type')} [{actor.get('name')}]"
    )


def dedup(event):
    return event.get("id")


def alert_context(event):
    return wiz_alert_context(event)
