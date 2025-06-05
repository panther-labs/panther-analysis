from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action", "") == "access_group.created"


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    next, _ = split_by_metadata(event)
    group_name = "<GROUP_NAME_NOT_FOUND>"
    if selected := select_from_list(next, "name", select_first=True):
        group_name = selected
    return f"Vercel: Access Group Created - [{actor}] created group [{group_name}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
