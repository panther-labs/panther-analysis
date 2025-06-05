from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") in (
        "integration.installed",
        "integration.updated",
        "integration.deleted",
    )


def title(event: PantherEvent) -> str:
    next, prev = split_by_metadata(event)
    integration_name = select_from_list(
        next, "name", filter=[("type", "integration")], select_first=True
    )
    integration_name = integration_name or select_from_list(
        prev, "name", filter=[("type", "integration")], select_first=True
    )
    integration_name = integration_name or "<INTEGRATION_NOT_FOUND>"
    actor_name = get_actor_name(event)
    action = event.get("action", "<ACTION_NOT_FOUND>")
    return f"Vercel: Integration {action} - [{actor_name}] {action.lower()} integration [{integration_name}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
