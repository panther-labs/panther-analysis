from panther_gsuite_helpers import gsuite_details_lookup as details_lookup
from panther_gsuite_helpers import gsuite_parameter_lookup as param_lookup
from panther_gsuite_helpers import gsuite_reports_alert_context

RESOURCE_CHANGE_EVENTS = {
    "create",
    "move",
    "upload",
    "edit",
}

PERMISSIVE_VISIBILITY = {
    "people_with_link",
    "public_on_the_web",
}


def rule(event):
    if event.deep_get("id", "applicationName") != "drive":
        return False

    details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
    return (
        bool(details)
        and param_lookup(details.get("parameters", {}), "visibility") in PERMISSIVE_VISIBILITY
    )


def dedup(event):
    user = event.deep_get("actor", "email")
    if user is None:
        user = event.deep_get("actor", "profileId", default="<UNKNOWN_PROFILEID>")
    return user


def title(event):
    details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
    doc_title = param_lookup(details.get("parameters", {}), "doc_title")
    share_settings = param_lookup(details.get("parameters", {}), "visibility")
    user = event.deep_get("actor", "email")
    if user is None:
        user = event.deep_get("actor", "profileId", default="<UNKNOWN_PROFILEID>")
    return (
        f"User [{user}]"
        f" modified a document [{doc_title}] that has overly permissive share"
        f" settings [{share_settings}]"
    )


def alert_context(event):
    return gsuite_reports_alert_context(event)
