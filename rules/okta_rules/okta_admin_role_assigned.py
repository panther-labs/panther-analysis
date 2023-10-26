import re

from panther_base_helpers import deep_get, okta_alert_context

ADMIN_PATTERN = re.compile(r"[aA]dministrator")


def rule(event):
    return (
        event.get("eventType", None) == "user.account.privilege.grant"
        and deep_get(event, "outcome", "result") == "SUCCESS"
        and bool(
            ADMIN_PATTERN.search(
                deep_get(event, "debugContext", "debugData", "privilegeGranted", default="")
            )
        )
    )


def dedup(event):
    return deep_get(event, "debugContext", "debugData", "requestId", default="<UNKNOWN_REQUEST_ID>")


def title(event):
    target = event.get("target", [{}])
    display_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else ""
    alternate_id = target[0].get("alternateId", "MISSING ALTERNATE ID") if target else ""
    privilege = deep_get(
        event, "debugContext", "debugData", "privilegeGranted", default="<UNKNOWN_PRIVILEGE>"
    )

    return (
        f"{deep_get(event, 'actor', 'displayName')} "
        f"<{deep_get(event, 'actor', 'alternateId')}> granted "
        f"[{privilege}] privileges to {display_name} <{alternate_id}>"
    )


def alert_context(event):
    return okta_alert_context(event)


def severity(event):
    if "Super administrator" in deep_get(
        event, "debugContext", "debugData", "privilegeGranted", default=""
    ):
        return "HIGH"
    return "INFO"
