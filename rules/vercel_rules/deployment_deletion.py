from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    split_by_metadata,
    select_from_list,
    get_actor_name,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "deployment.deleted"


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    _, prev = split_by_metadata(event)
    deployment_id = (
        select_from_list(prev, "id", filter=[("type", "deployment")], select_first=True)
        or "<DEPLOYMENT_ID_NOT_FOUND>"
    )
    deployment_url = (
        select_from_list(
            prev,
            "metadata",
            filter=[("type", "deployment")],
            subkey="url",
            select_first=True,
        )
        or "<DEPLOYMENT_URL_NOT_FOUND>"
    )
    return f"Vercel: Deployment Deleted - [{actor}] deleted deployment [{deployment_id}] (URL: [{deployment_url}])"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
