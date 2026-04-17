from panther_notion_helpers import notion_alert_context


def rule(event):
    added = (
        event.deep_get("event", "type", default="") == "teamspace.permissions.member_added"
        and event.deep_get("event", "details", "role", default="") == "owner"
    )
    updated = (
        event.deep_get("event", "type", default="") == "teamspace.permissions.member_role_updated"
        and event.deep_get("event", "details", "new_role", default="") == "owner"
    )
    return added or updated


def title(event):
    actor = event.deep_get("event", "actor", "person", "email", default="NO_ACTOR_FOUND")
    member = event.deep_get(
        "event", "details", "member", "person", "email", default="NO_MEMBER_FOUND"
    )
    teamspace = event.deep_get("event", "details", "target", "name", default="NO_TEAMSPACE_FOUND")
    return f"[{actor}] added [{member}] as owner of [{teamspace}] Teamspace"


def alert_context(event):
    return notion_alert_context(event)
