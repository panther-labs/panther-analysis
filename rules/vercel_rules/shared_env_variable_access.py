from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    select_from_list,
    split_by_metadata,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") == "shared_env_variable.decrypted"


def title(event: PantherEvent) -> str:
    # i couldnt trigger this log, so i just assume things
    actor = get_actor_name(event)
    next, prev = split_by_metadata(event)
    env_var = select_from_list(
        next,
        "metadata",
        filter=[("type", "envVariable")],
        subkey="key",
        select_first=True,
    )
    env_var = env_var or select_from_list(
        prev,
        "metadata",
        filter=[("type", "envVariable")],
        subkey="key",
        select_first=True,
    )
    env_var = env_var or "<ENV_VAR_NOT_FOUND>"
    return f"Vercel: Shared Env Variable Access - [{actor}] accessed [{env_var}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
