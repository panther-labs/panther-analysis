from panther_core import PantherEvent


from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "alias.created"


def title(event: PantherEvent) -> str:
    next, prev = split_by_metadata(event)
    new_alias = (
        select_from_list(next, "metadata", "alias", select_first=True)
        or "<NEW_ALIAS_NOT_FOUND>"
    )
    old_alias = (
        select_from_list(prev, "metadata", "alias", select_first=True)
        or "<OLD_ALIAS_NOT_FOUND>"
    )
    project_name = (
        select_from_list(next, "name", select_first=True) or "<PROJECT_NAME_NOT_FOUND>"
    )
    actor = get_actor_name(event)
    return f"Vercel: Alias Created - [{actor}] created alias [{new_alias}] for project [{project_name}] (previous alias: [{old_alias}])"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
