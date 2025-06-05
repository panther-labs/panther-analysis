from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "team.member.added"


def title(event: PantherEvent) -> str:
    actor_name = get_actor_name(event)
    next, _ = split_by_metadata(event)
    invitee_email = select_from_list(
        next, "metadata", subkey="email", filter=[("type", "invite")], select_first=True
    )
    return f"Vercel: Team Member Added - [{actor_name}] added user [{invitee_email}] to the team"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
