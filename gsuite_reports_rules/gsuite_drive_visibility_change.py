from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_parameter_lookup as param_lookup


def rule(event):
    if deep_get(event, "id", "applicationName") != "drive":
        return False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and param_lookup(details.get("parameters", {}), "visibility_change") == "external"
        ):
            return True

    return False


def dedup(event):
    return deep_get(event, "actor", "email", default="<UNKNOWN_EMAIL>")


def title(event):
    return "User [{}] made a document externally visible for the first time".format(
        deep_get(event, "actor", "email", default="<UNKNOWN_EMAIL>")
    )
