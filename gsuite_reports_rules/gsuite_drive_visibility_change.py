from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

#
VISIBILITY = [
    "people_with_link",
    "public_on_the_web",
    "shared_externally",
    "unknown"
    ]

def rule(event):
    if deep_get(event, "id", "applicationName") != "drive":
        return False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and param_lookup(details.get("parameters", {}), "visibility_change") == "external"
            and param_lookup(details.get("parameters", {}), "visibility") in VISIBILITY
        ):
            return True

    return False


def dedup(event):
    doc_title = "<UNKNOWN_DOC_TITLE>"
    for detail in event.get("events", [{}]):
        if detail.get("type") == "acl_change":
            if param_lookup(detail.get("parameters", {}), "doc_title"):
                doc_title = param_lookup(detail.get("parameters", {}), "doc_title")
                break
    return doc_title


def title(event):
    target_user_email = "<EMAIL_UNKNOWN>"
    doc_title = "<UNKNOWN_DOC_TITLE>"
    for detail in event.get("events", [{}]):
        if detail.get("type") == "acl_change":
            if param_lookup(detail.get("parameters", {}), "doc_title"):
                doc_title = param_lookup(detail.get("parameters", {}), "doc_title")
            if param_lookup(detail.get("parameters", {}), "target_user"):
                target_user_email = param_lookup(detail.get("parameters", {}), "target_user")
            if param_lookup(detail.get("parameters", {}), "target_domain"):
                target_domain = param_lookup(detail.get("parameters", {}), "target_domain")
            break
    if target_user_email != "<EMAIL_UNKNOWN>":
        sharing_scope = target_user_email
    elif target_domain == "all":
        sharing_scope = f"all domains"
    else:
        sharing_scope = target_domain
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] made a document "
        f"[{doc_title}] externally visible to [{sharing_scope}]"
    )
