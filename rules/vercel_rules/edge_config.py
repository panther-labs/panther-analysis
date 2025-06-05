from panther_core import PantherEvent
from panther_vercel_helpers import create_vercel_context, get_actor_name


def rule(event: PantherEvent) -> bool:
    return event.get("action", "").startswith("edge_config.")


def title(event: PantherEvent) -> str:
    # TODO: i could't trigger log for this, so we dont have encrihment info
    actor = get_actor_name(event)
    return f"Vercel: Edge Config Changed - [{actor}] modified edge configurations"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
