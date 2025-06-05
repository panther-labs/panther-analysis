from panther_core import PantherEvent

from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") in (
        "project.transfer.started",
        "project.transfer_out.completed",
    )


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    next, prev = split_by_metadata(event)
    project_name = (
        select_from_list(prev, "name", filter=[("type", "project")], select_first=True)
        or "<PROJECT_NAME_NOT_FOUND>"
    )
    prev_owner = (
        select_from_list(
            prev,
            "metadata",
            filter=[("type", "team"), ("type", "user")],
            subkey="slug",
            select_first=True,
        )
        or "<OWNER_NOT_FOUND>"
    )
    next_owner = (
        select_from_list(
            next,
            "metadata",
            filter=[("type", "team"), ("type", "user")],
            subkey="slug",
            select_first=True,
        )
        or "<OWNER_NOT_FOUND>"
    )
    action = event.get("action", "<ACTION_NOT_FOUND>")
    return f"Vercel: Project Transfer [{action.capitalize()}] - [{actor}] initiated transfer of project [{project_name}] from [{prev_owner}] to [{next_owner}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
