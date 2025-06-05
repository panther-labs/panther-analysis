from panther_core import PantherEvent


def create_vercel_context(event: PantherEvent) -> dict:
    actor = event.get("actor", {})
    context = event.get("context", {})
    return {
        "actor_name": actor.get("name", "<ACTOR_NOT_FOUND>"),
        "actor_id": actor.get("id", "<ACTOR_ID_NOT_FOUND>"),
        "action": event.get("action", "<ACTION_NOT_FOUND>"),
        "timestamp": event.get("occurred_at", "<TIMESTAMP_NOT_FOUND>"),
        "location": context.get("location", "<LOCATION_NOT_FOUND>"),
        "user_agent": context.get("user_agent", "<USER_AGENT_NOT_FOUND>"),
    }


def split_by_metadata(event) -> tuple[list, list]:
    next = []
    previous = []
    for target in event.get("targets", []):
        if target.get("metadata", {}).get("_from") == '"next"':
            next.append(target)
        elif target.get("metadata", {}).get("_from") == '"previous"':
            previous.append(target)
    return next, previous


def select_from_list(
    inputs: list,
    key: str | None = None,
    subkey: str | None = None,
    filter: list[tuple[str, str]] | None = None,
    select_first: bool = False,
) -> list[str] | None:
    selectee = inputs
    if filter:
        selectee = [
            item for item in selectee if any(item.get(k) == v for k, v in filter)
        ]
    if key:
        selectee = [el for item in selectee if (el := item.get(key))]
    if subkey:
        selectee = [el for item in selectee if (el := item.get(subkey))]
    if select_first:
        return selectee[0] if selectee else None
    return selectee or None


def get_actor_name(event) -> str:
    return event.get("actor", {}).get("name", "<ACTOR_NOT_FOUND>")
