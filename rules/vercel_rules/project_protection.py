from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    split_by_metadata,
    select_from_list,
    get_actor_name,
)


def rule(event: PantherEvent) -> bool:
    return event.get("action") in [
        "project.password_protection.disabled",
        "project.sso_protection.disabled",
    ]


def title(event: PantherEvent) -> str:
    _next, prev = split_by_metadata(event)
    project_name = (
        select_from_list(prev, "name", filter=[("type", "project")], select_first=True)
        or "<PROJECT_NOT_FOUND>"
    )
    actor = get_actor_name(event)
    protection_type = "SSO" if "sso" in event.get("action", "") else "Password"
    return f"Vercel: Project {protection_type} Protection Disabled - [{actor}] disabled {protection_type} protection for project [{project_name}]"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
