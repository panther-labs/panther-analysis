from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    split_by_metadata,
    select_from_list,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") in ("domain.moved_out", "domain.moved_in")


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    next, prev = split_by_metadata(event)
    domain_name = (
        select_from_list(
            prev,
            "name",
            filter=[("type", "domain"), ("type", "user")],
            select_first=True,
        )
        or "<DOMAIN_NOT_FOUND>"
    )
    prev_owner = (
        select_from_list(
            prev, "name", filter=[("type", "user"), ("type", "team")], select_first=True
        )
        or "<OWNER_NOT_FOUND>"
    )
    next_owner = (
        select_from_list(
            next, "name", filter=[("type", "user"), ("type", "team")], select_first=True
        )
        or "<OWNER_NOT_FOUND>"
    )
    return f"Vercel: Domain Moved - [{actor}] moved domain [{domain_name}] from [{prev_owner}] to [{next_owner}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
