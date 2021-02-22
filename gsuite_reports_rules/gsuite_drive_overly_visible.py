from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup
from panther_base_helpers import deep_get

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
    if deep_get(event, "id", "applicationName") != "drive":
        return False

    details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
    return (
        bool(details)
        and param_lookup(details.get("parameters", {}), "visibility") in PERMISSIVE_VISIBILITY
    )


def dedup(event):
    return deep_get(event, "actor", "email", default="<UNKNOWN_EMAIL>")


def title(event):
    return "User [{}] modified a document that has overly permissive share settings".format(
        deep_get(event, "actor", "email", default="<UNKNOWN_EMAIL>")
    )
