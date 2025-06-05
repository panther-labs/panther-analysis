from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    split_by_metadata,
    select_from_list,
)
from datetime import datetime


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "project.deleted"


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    _next, prev = split_by_metadata(event)
    project = (
        select_from_list(prev, filter=[("type", "project")], select_first=True) or {}
    )
    project_name = project.get("name", "<PROJECT_NOT_FOUND>")
    deleted_at = project.get("metadata", {}).get("deletedAt", 0)
    deleted_at = datetime.fromtimestamp(int(deleted_at) / 1000).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    return f"Vercel: Project Deleted - [{actor}] deleted project [{project_name}] at [{deleted_at}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
