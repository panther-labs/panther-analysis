from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

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
    doc_title = "UNKNOWN_TITLE"
    details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
    doc_title = param_lookup(details.get("parameters", {}), "doc_title")
    share_settings = param_lookup(details.get("parameters", {}), "visibility")
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
        f" modified a document [{doc_title}] that has overly permissive share"
        f" settings [{share_settings}]"
    )
