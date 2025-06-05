from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") in (
        "domain.record.created",
        "domain.record.deleted",
        "domain.record.updated",
    )


def title(event: PantherEvent) -> str:
    # TODO: couldn't trigger this log, so i just assume things
    actor = get_actor_name(event)
    next, prev = split_by_metadata(event)
    domain = select_from_list(
        next, "name", filter=[("type", "domain")], select_first=True
    )
    domain = domain or select_from_list(
        prev, "name", filter=[("type", "domain")], select_first=True
    )
    domain = domain or "<DOMAIN_NOT_FOUND>"
    action = event.get("action", "<ACTION_NOT_FOUND>").split(".")[-1].upper()
    return f"Vercel: DNS Record {action.capitalize()} - [{actor}] {action.lower()} a DNS record for domain [{domain}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
