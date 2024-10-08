import re

from panther_okta_helpers import okta_alert_context

ADMIN_PATTERN = re.compile(r"[aA]dministrator")


def rule(event):
    return (
        event.get("eventType", None) == "user.account.privilege.grant"
        and event.deep_get("outcome", "result") == "SUCCESS"
        and bool(
            ADMIN_PATTERN.search(
                event.deep_get("debugContext", "debugData", "privilegeGranted", default="")
            )
        )
    )


def dedup(event):
    return event.deep_get("debugContext", "debugData", "requestId", default="<UNKNOWN_REQUEST_ID>")


def title(event):
    target = event.get("target", [{}])
    display_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else ""
    alternate_id = target[0].get("alternateId", "MISSING ALTERNATE ID") if target else ""
    privilege = event.deep_get(
        "debugContext", "debugData", "privilegeGranted", default="<UNKNOWN_PRIVILEGE>"
    )

    return (
        f"{event.deep_get('actor', 'displayName')} "
        f"<{event.deep_get('actor', 'alternateId')}> granted "
        f"[{privilege}] privileges to {display_name} <{alternate_id}>"
    )


def alert_context(event):
    return okta_alert_context(event)


def severity(event):
    if "Super administrator" in event.deep_get(
        "debugContext", "debugData", "privilegeGranted", default=""
    ):
        return "HIGH"
    return "INFO"
