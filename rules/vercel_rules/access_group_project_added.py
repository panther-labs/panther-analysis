from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "access_group.project.added"


def title(event: PantherEvent) -> str:
    next, _ = split_by_metadata(event)
    group_id = "<GROUP_ID_NOT_FOUND>"
    role_name = "<ROLE_NAME_NOT_FOUND>"
    if _group_id := select_from_list(
        next, "id", filter=[("type", "accessGroup")], select_first=True
    ):
        group_id = _group_id
    if _role_name := select_from_list(
        next, "metadata", filter=[("type", "project")], subkey="role", select_first=True
    ):
        role_name = _role_name
    actor = get_actor_name(event)

    return f"Vercel: Project Added to Access Group - [{actor}] added a project to access group [{group_id}] with role [{role_name}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
