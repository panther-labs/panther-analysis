from panther_core import PantherEvent
from panther_vercel_helpers import create_vercel_context, get_actor_name


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "domain.deleted"


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    domain = event.deep_get("domain", "name", default="<DOMAIN_NOT_FOUND>")
    return f"Vercel: Domain Deleted - [{actor}] deleted domain [{domain}]"


def alert_context(event: PantherEvent) -> dict:
    context = create_vercel_context(event)
    return context | {
        "domain": event.deep_get("domain", "name", default="<DOMAIN_NOT_FOUND>"),
    }
