from panther_core import PantherEvent
from panther_vercel_helpers import (
    create_vercel_context,
    get_actor_name,
    split_by_metadata,
    select_from_list,
)
from datetime import datetime, timedelta

ACTION = ""
REQUEST_RANGE = timedelta()


def rule(event: PantherEvent) -> bool:
    global ACTION, REQUEST_RANGE

    match event.get("action"):
        case "auditlog.export.requested":
            ACTION = "requested"
            next, _ = split_by_metadata(event)
            audit_log_export = (
                select_from_list(
                    next,
                    "metadata",
                    filter=[("type", "auditLogExport")],
                    select_first=True,
                )
                or {}
            )
            from_time = audit_log_export.get("from", 0)
            to_time = audit_log_export.get("to", 0)
            REQUEST_RANGE = datetime.fromtimestamp(
                int(to_time) / 1000
            ) - datetime.fromtimestamp(int(from_time) / 1000)
        case "auditlog.export.downloaded":
            ACTION = "downloaded"
        case _:
            return False
    return True


def title(event: PantherEvent) -> str:
    actor = get_actor_name(event)
    if REQUEST_RANGE > timedelta(days=30):
        range_in_days = REQUEST_RANGE.days
        return f"Vercel: Large Audit Log Export {ACTION.capitalize()} - [{actor}] {ACTION} an audit log spanning [{range_in_days} days]"
    return f"Vercel: Audit Log {ACTION.capitalize()} - [{actor}] {ACTION} an audit log"


def severity(_event) -> str:
    global REQUEST_RANGE, ACTION
    match ACTION:
        case "requested":
            if REQUEST_RANGE > timedelta(days=30):
                return "HIGH"
            return "MEDIUM"
        case "downloaded":
            return "HIGH"


def alert_context(event: PantherEvent) -> dict:
    return create_vercel_context(event)
