from panther_notion_helpers import notion_alert_context

EVENTS = (
    "teamspace.settings.allow_public_page_sharing_setting_updated",
    "teamspace.settings.allow_guests_setting_updated",
    "teamspace.settings.allow_content_export_setting_updated",
    "workspace.settings.allow_public_page_sharing_setting_updated",
    "workspace.settings.allow_guests_setting_updated",
    "workspace.settings.allow_content_export_setting_updated",
)


def rule(event):
    return all(
        [
            event.deep_get("event", "type", default="") in EVENTS,
            event.deep_get("event", "details", "state", default="") == "enabled",
        ]
    )


def title(event):
    actor = event.deep_get("event", "actor", "person", "email", default="NO_ACTOR_FOUND")
    action = event.deep_get("event", "type", default="NO.EVENT.FOUND").split(".")[2]
    teamspace = event.deep_get("event", "details", "target", "name", default=None)
    if teamspace:
        return f"[{actor}] enabled [{action}] for [{teamspace}] Teamspace"
    return f"[{actor}] enabled [{action}] for Workspace"


def alert_context(event):
    return notion_alert_context(event)
