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


def rule(event):
    if deep_get(event, "id", "applicationName") != "drive":
        return False

    #########
    # for target_domain
    change_document_visibility = False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and details.get("name") == "change_document_visibility"
            and param_lookup(details.get("parameters", {}), "new_value") != ["private"]
            and param_lookup(details.get("parameters", {}), "target_domain") not in EXCLUDED_DOMAINS
            and param_lookup(details.get("parameters", {}), "visibility") in VISIBILITY
        ):
            global TARGET_DOMAIN # pylint: disable=global-statement
            TARGET_DOMAIN = param_lookup(details.get("parameters", {}), "target_domain")
            global NEW_VISIBILITY # pylint: disable=global-statement
            NEW_VISIBILITY = param_lookup(details.get("parameters", {}), "visibility")
            global DOC_TITLE # pylint: disable=global-statement
            DOC_TITLE = param_lookup(details.get("parameters", {}), "doc_title")

            change_document_visibility = True
            break

    # "change_document_access_scope" events are always paired with
    # "change_document_visibility" events. the "target_domain" and
    # "visibility" attributes are the same
    # the set of a "change_document_access_scope" and a
    # "change_document_visibility" is paired with a second set of
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
                global ACCESS_SCOPE # pylint: disable=global-statement
                ACCESS_SCOPE = param_lookup(details.get("parameters", {}), "new_value")
        return True

    # TODO: confirm that change_user_access events are mutually exclusive with the above events
    # split this out
    #########
    # for target_user
    change_user_access = False

    for details in event.get("events", [{}]):
        if (
            details.get("type") == "acl_change"
            and details.get("name") == "change_user_access"
            and param_lookup(details.get("parameters", {}), "new_value") != ["none"]
        ):
            global TARGET_USER_EMAIL # pylint: disable=global-statement
            TARGET_USER_EMAIL = param_lookup(details.get("parameters", {}), "target_user")
            DOC_TITLE = param_lookup(details.get("parameters", {}), "doc_title")
            ACCESS_SCOPE = param_lookup(details.get("parameters", {}), "new_value")

            change_user_access = True
            break

    if change_user_access:
        return True

    return False


def dedup(_):
    return DOC_TITLE


def title(event):

    if TARGET_USER_EMAIL != "<UNKNOWN_USER>":
        sharing_scope = TARGET_USER_EMAIL
        # TODO: make sure this options only appears if a target_user is specified
        if NEW_VISIBILITY == "shared_externally":
            sharing_scope = sharing_scope + " (outside the document's current domain)"
    # TODO: make sure there is no target_domain if there is a target_user
    elif TARGET_DOMAIN == "all":
        sharing_scope = "the entire internet"
        # TODO: make sure these options only appear with the "all" target_domain
        if NEW_VISIBILITY == "people_with_link":
            sharing_scope = sharing_scope + " (anyone with the link)"
        elif NEW_VISIBILITY == "public_on_the_web":
            sharing_scope = sharing_scope + " (link not required)"
    else:
        sharing_scope = f"the {TARGET_DOMAIN} domain"
        # TODO: make sure these options only appear with a specific target_domain (not "all")
        if NEW_VISIBILITY == "people_within_domain_with_link":
            sharing_scope = sharing_scope + f" (anyone in {TARGET_DOMAIN} with the link)"
        elif NEW_VISIBILITY == "public_in_the_domain":
            sharing_scope = sharing_scope + f" (anyone in {TARGET_DOMAIN})"

    global ACCESS_SCOPE # pylint: disable=global-statement
    # TODO: confirm multiValue always has one element
    if ACCESS_SCOPE == ["can_view"]:
        ACCESS_SCOPE = "view"
    elif ACCESS_SCOPE == ["can_comment"]:
        ACCESS_SCOPE = "comment"
    elif ACCESS_SCOPE == ["can_edit"]:
        ACCESS_SCOPE = "edit"

    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}] made the document "
        f"[{DOC_TITLE}] externally visible to [{sharing_scope}] with [{ACCESS_SCOPE}] access"
    )
