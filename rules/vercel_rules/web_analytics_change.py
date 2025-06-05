from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") in (
        "project.web-analytics.enabled",
        "project.web-analytics.disabled",
    )


def title(event: PantherEvent) -> str:
    match event.get("action"):
        case "project.web-analytics.enabled":
            action = "enabled"
        case "project.web-analytics.disabled":
            action = "disabled"
    actor_name = event.get("actor", {}).get("name", "<ACTOR_NOT_FOUND>")
    next, _ = split_by_metadata(event)
    project_name = (
        select_from_list(next, "name", filter=[("type", "project")], select_first=True)
        or "<PROJECT_NOT_FOUND>"
    )
    return f"Vercel: Web Analytics {action} - [{actor_name}] modified web analytics for project [{project_name}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
