from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)

ACTION = ""
CERT_ID = ""
CUSTOM = False


def rule(event: PantherEvent) -> bool:
    global ACTION, CUSTOM, CERT_ID
    match event.get("action"):
        case "cert.created":
            ACTION = "created"
        case "cert.renewed":
            ACTION = "renewed"
        case "cert.deleted":
            ACTION = "deleted"
        case _:
            return False

    next, _ = split_by_metadata(event)
    cert = select_from_list(next, filter=[("type", "cert")], select_first=True) or {}
    CUSTOM = cert.get("custom", False)
    CERT_ID = cert.get("id", "<CERT_ID_NOT_FOUND>")
    return True


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    return f"Vercel: Certificate {ACTION.capitalize()} - [{actor}] {ACTION} a {'system-generated' if not CUSTOM else 'custom'} certificate [{CERT_ID}]"


def severity(_event):
    if CUSTOM:
        return "HIGH"
    return "LOW"


def alert_context(event: PantherEvent) -> dict:
    context = create_vercel_context(event)
    return context | {
        "cert_id": CERT_ID,
    }
