from panther_core import PantherEvent
import json
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "team.member.role.updated"


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    next, prev = split_by_metadata(event)
    new_role = old_role = ""
    member_email = select_from_list(
        next, "metadata", subkey="email", filter=[("type", "user")], select_first=True
    )
    if _old_team_info := select_from_list(
        prev, "metadata", subkey="members", filter=[("type", "team")], select_first=True
    ):
        if len(old_team_info := json.loads(_old_team_info)) > 0:
            old_role = old_team_info[0]["role"]
    if _new_team_info := select_from_list(
        next, "metadata", subkey="members", filter=[("type", "team")], select_first=True
    ):
        if len(new_team_info := json.loads(_new_team_info)) > 0:
            new_role = new_team_info[0]["role"]
    return f"Vercel: Team Member Role Changed - [{actor}] changed role of [{member_email}] from [{old_role}] to [{new_role}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
