from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

EXCLUDED_DOMAINS = {"example.com"}

VISIBILITY = {
    "people_with_link",
    "people_within_domain_with_link",
    "public_on_the_web",
    "shared_externally",
    "unknown",
}

ALERT_DETAILS = {}

# Events where documents have changed perms due to parent folder change
INHERITANCE_EVENTS = {
    "change_user_access_hierarchy_reconciled",
    "change_document_access_scope_hierarchy_reconciled",
}


def init_alert_details(log):
    global ALERT_DETAILS  # pylint: disable=global-statement
    ALERT_DETAILS[log] = {
        "ACCESS_SCOPE": "<UNKNOWN_ACCESS_SCOPE>",
        "DOC_TITLE": "<UNKNOWN_TITLE>",
        "NEW_VISIBILITY": "<UNKNOWN_VISIBILITY>",
        "TARGET_USER_EMAILS": ["<UNKNOWN_USER>"],
        "TARGET_DOMAIN": "<UNKNOWN_DOMAIN>",
    }


def user_is_external(target_user):
    for domain in EXCLUDED_DOMAINS:
        if domain in target_user:
            return False
    return True


def rule(event):
    if deep_get(event, "id", "applicationName") != "drive":
        return False

    # Events that have the types in INHERITANCE_EVENTS are
    # changes to documents and folders that occur due to
    # a change in the parent folder's permission. We ignore
    # these events to prevent every folder change from
    # generating multiple alerts.
    if deep_get(event, "events", "name") in INHERITANCE_EVENTS:
        return False

    log = event.get("p_row_id")
    init_alert_details(log)

    #########
    # for visibility changes that apply to a domain, not a user
    change_document_visibility = False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and details.get("name") == "change_document_visibility"
            and param_lookup(details.get("parameters", {}), "new_value") != ["private"]
            and param_lookup(details.get("parameters", {}), "target_domain") not in EXCLUDED_DOMAINS
            and param_lookup(details.get("parameters", {}), "visibility") in VISIBILITY
        ):
            ALERT_DETAILS[log]["TARGET_DOMAIN"] = param_lookup(
                details.get("parameters", {}), "target_domain"
            )
            ALERT_DETAILS[log]["NEW_VISIBILITY"] = param_lookup(
                details.get("parameters", {}), "visibility"
            )
            ALERT_DETAILS[log]["DOC_TITLE"] = param_lookup(
                details.get("parameters", {}), "doc_title"
            )

            change_document_visibility = True
            break

    # "change_document_visibility" events are always paired with
    # "change_document_access_scope" events. the "target_domain" and
    # "visibility" attributes are equivalent.
    if change_document_visibility:
        for details in event.get("events", [{}]):
            if (
                details.get("type") == "acl_change"
                and details.get("name") == "change_document_access_scope"
                and param_lookup(details.get("parameters", {}), "new_value") != ["none"]
            ):
                ALERT_DETAILS[log]["ACCESS_SCOPE"] = param_lookup(
                    details.get("parameters", {}), "new_value"
                )
        return True

    #########
    # for visibility changes that apply to a user
    # there is a change_user_access event for each user
    # change_user_access and change_document_visibility events are
    # not found in the same report
    change_user_access = False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and details.get("name") == "change_user_access"
            and param_lookup(details.get("parameters", {}), "new_value") != ["none"]
            and user_is_external(param_lookup(details.get("parameters", {}), "target_user"))
        ):
            if ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
                ALERT_DETAILS[log]["TARGET_USER_EMAILS"].append(
                    param_lookup(details.get("parameters", {}), "target_user")
                )
            else:
                ALERT_DETAILS[log]["TARGET_USER_EMAILS"] = [
                    param_lookup(details.get("parameters", {}), "target_user")
                ]
                ALERT_DETAILS[log]["DOC_TITLE"] = param_lookup(
                    details.get("parameters", {}), "doc_title"
                )
                ALERT_DETAILS[log]["ACCESS_SCOPE"] = param_lookup(
                    details.get("parameters", {}), "new_value"
                )

            change_user_access = True

    return change_user_access


def alert_context(event):
    log = event.get("p_row_id")
    if ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
        return {"target users": ALERT_DETAILS[log]["TARGET_USER_EMAILS"]}
    return {}


def dedup(event):
    log = event.get("p_row_id")
    return ALERT_DETAILS[log]["DOC_TITLE"]


def title(event):
    log = event.get("p_row_id")
    if ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
        if len(ALERT_DETAILS[log]["TARGET_USER_EMAILS"]) == 1:
            sharing_scope = ALERT_DETAILS[log]["TARGET_USER_EMAILS"][0]
        else:
            sharing_scope = "multiple users"
        if ALERT_DETAILS[log]["NEW_VISIBILITY"] == "shared_externally":
            sharing_scope += " (outside the document's current domain)"
    elif ALERT_DETAILS[log]["TARGET_DOMAIN"] == "all":
        sharing_scope = "the entire internet"
        if ALERT_DETAILS[log]["NEW_VISIBILITY"] == "people_with_link":
            sharing_scope += " (anyone with the link)"
        elif ALERT_DETAILS[log]["NEW_VISIBILITY"] == "public_on_the_web":
            sharing_scope += " (link not required)"
    else:
        sharing_scope = f"the {ALERT_DETAILS[log]['TARGET_DOMAIN']} domain"
        if ALERT_DETAILS[log]["NEW_VISIBILITY"] == "people_within_domain_with_link":
            sharing_scope += f" (anyone in {ALERT_DETAILS['TARGET_DOMAIN']} with the link)"
        elif ALERT_DETAILS[log]["NEW_VISIBILITY"] == "public_in_the_domain":
            sharing_scope += f" (anyone in {ALERT_DETAILS['TARGET_DOMAIN']})"

    alert_access_scope = ALERT_DETAILS[log]["ACCESS_SCOPE"][0].replace("can_", "")

    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}] made the document "
        f"[{ALERT_DETAILS[log]['DOC_TITLE']}] externally visible to [{sharing_scope}] with "
        f"[{alert_access_scope}] access"
    )
