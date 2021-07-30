from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

EXCLUDED_DOMAINS = {"example.com"}

VISIBILITY = {"people_with_link", "public_on_the_web", "shared_externally", "unknown"}

ALERT_DETAILS = {
    "ACCESS_SCOPE": "<UNKNOWN_ACCESS_SCOPE>",
    "DOC_TITLE": "<UNKNOWN_TITLE>",
    "NEW_VISIBILITY": "<UNKNOWN_VISIBILITY>",
    "TARGET_USER_EMAIL": "<UNKNOWN_USER>",
    "TARGET_DOMAIN": "<UNKNOWN_DOMAIN>",
}

def reset_alert_details():
    ALERT_DETAILS = {
        "ACCESS_SCOPE": "<UNKNOWN_ACCESS_SCOPE>",
        "DOC_TITLE": "<UNKNOWN_TITLE>",
        "NEW_VISIBILITY": "<UNKNOWN_VISIBILITY>",
        "TARGET_USER_EMAIL": "<UNKNOWN_USER>",
        "TARGET_DOMAIN": "<UNKNOWN_DOMAIN>",
    }


def rule(event):
    if deep_get(event, "id", "applicationName") != "drive":
        return False

    reset_alert_details()

    #########
    # for visibility changes that apply to a domain
    change_document_visibility = False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and details.get("name") == "change_document_visibility"
            and param_lookup(details.get("parameters", {}), "new_value") != ["private"]
            and param_lookup(details.get("parameters", {}), "target_domain") not in EXCLUDED_DOMAINS
            and param_lookup(details.get("parameters", {}), "visibility") in VISIBILITY
        ):
            ALERT_DETAILS["TARGET_DOMAIN"] = param_lookup(
                details.get("parameters", {}), "target_domain"
            )
            ALERT_DETAILS["NEW_VISIBILITY"] = param_lookup(
                details.get("parameters", {}), "visibility"
            )
            ALERT_DETAILS["DOC_TITLE"] = param_lookup(details.get("parameters", {}), "doc_title")

            change_document_visibility = True
            break

    # "change_document_visibility" events are always paired with
    # "change_document_access_scope" events. the "target_domain" and
    # "visibility" attributes are the same
    # the set of a "change_document_visibility" and a
    # "change_document_access_scope" is paired with a second set of
    # these events. the first pair of events represents the "old"
    # domain and visibility, and the second pair represents the
    # "new" domain and visibility
    if change_document_visibility:
        for details in event.get("events", [{}]):
            if (
                details.get("type") == "acl_change"
                and details.get("name") == "change_document_access_scope"
                and param_lookup(details.get("parameters", {}), "new_value") != ["none"]
            ):
                ALERT_DETAILS["ACCESS_SCOPE"] = param_lookup(
                    details.get("parameters", {}), "new_value"
                )
        return True

    #########
    # for visibility changes that apply to a specific user
    # there is only one change_user_access event
    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and details.get("name") == "change_user_access"
            and param_lookup(details.get("parameters", {}), "new_value") != ["none"]
        ):
            ALERT_DETAILS["TARGET_USER_EMAIL"] = param_lookup(
                details.get("parameters", {}), "target_user"
            )
            ALERT_DETAILS["DOC_TITLE"] = param_lookup(details.get("parameters", {}), "doc_title")
            ALERT_DETAILS["ACCESS_SCOPE"] = param_lookup(details.get("parameters", {}), "new_value")

            return True

    return False


def dedup(_):
    return ALERT_DETAILS["DOC_TITLE"]


def title(event):

    if ALERT_DETAILS["TARGET_USER_EMAIL"] != "<UNKNOWN_USER>":
        sharing_scope = ALERT_DETAILS["TARGET_USER_EMAIL"]
        if ALERT_DETAILS["NEW_VISIBILITY"] == "shared_externally":
            sharing_scope += " (outside the document's current domain)"
    elif ALERT_DETAILS["TARGET_DOMAIN"] == "all":
        sharing_scope = "the entire internet"
        if ALERT_DETAILS["NEW_VISIBILITY"] == "people_with_link":
            sharing_scope += " (anyone with the link)"
        elif ALERT_DETAILS["NEW_VISIBILITY"] == "public_on_the_web":
            sharing_scope += " (link not required)"
    else:
        sharing_scope = f"the {ALERT_DETAILS['TARGET_DOMAIN']} domain"
        if ALERT_DETAILS["NEW_VISIBILITY"] == "people_within_domain_with_link":
            sharing_scope += f" (anyone in {ALERT_DETAILS['TARGET_DOMAIN']} with the link)"
        elif ALERT_DETAILS["NEW_VISIBILITY"] == "public_in_the_domain":
            sharing_scope += f" (anyone in {ALERT_DETAILS['TARGET_DOMAIN']})"

    alert_access_scope = ALERT_DETAILS["ACCESS_SCOPE"][0].replace("can_", "")

    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}] made the document "
        f"[{ALERT_DETAILS['DOC_TITLE']}] externally visible to [{sharing_scope}] with "
        f"[{alert_access_scope}] access"
    )
