from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_parameter_lookup as param_lookup


def rule(event):
    # This Tuple refers to events where documents have changed perms due to parent folder change
    inheritance_events = (
        "change_user_access_hierarchy_reconciled",
        "change_document_access_scope_hierarchy_reconciled",
    )

    if deep_get(event, "id", "applicationName") != "drive":
        return False

    if deep_get(event, "events", "name") in inheritance_events:
        return False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and param_lookup(details.get("parameters", {}), "visibility_change") == "external"
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
            break
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] made a document "
        f"[{doc_title}] externally visible for the first time with [{target_user_email}]"
    )
