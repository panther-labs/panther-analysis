import datetime

from panther_base_helpers import pattern_match, pattern_match_list

COMPANY_DOMAIN = "your-company-name.com"
EXCEPTION_PATTERNS = {
    # The glob pattern for the document title (lowercased)
    "1 document title p*": {  # allow any title "all"
        "allowed_to_send": {
            "alice@acme.com",
            "samuel@acme.com",
            "nathan@acme.com",
            "barry@acme.com",
            # Allow any user
            # "all"
            # Allow any user in a specific domain
            # "*@acme.com"
        },
        "allowed_to_receive": {
            "alice@abc.com",
            "samuel@abc.com",
            "nathan@abc.com",
            "barry@abc.com",
            # Allow any user
            # "all"
            # Allow any user in a specific domain
            # "*@acme.com"
        },
        # The time limit for how long the file share stays valid
        "allowed_until": datetime.datetime(year=2030, month=6, day=2),
    },
    "2 document title p*": {
        "allowed_to_send": {
            "alice@abc.com",
        },
        "allowed_to_receive": {
            "*@acme.com",
        },
        # The time limit for how long the file share stays valid
        "allowed_until": datetime.datetime(year=2030, month=6, day=2),
    },
}


def _check_acl_change_event(actor_email, event):
    # For GSuite.ActivityEvent, parameters is a dict, not an array
    parameters = event.get("parameters", {})

    doc_title = parameters.get("doc_title", "TITLE_UNKNOWN")
    old_visibility = parameters.get("old_visibility", "OLD_VISIBILITY_UNKNOWN")
    new_visibility = parameters.get("visibility", "NEW_VISIBILITY_UNKNOWN")
    target_user = parameters.get("target_user") or parameters.get("target_domain") or "USER_UNKNOWN"
    current_time = datetime.datetime.now()

    if (
        new_visibility == "shared_externally"
        and old_visibility == "private"
        and not target_user.endswith(f"@{COMPANY_DOMAIN}")
    ):
        # This is a dangerous share, check exceptions:

        for pattern, details in EXCEPTION_PATTERNS.items():
            proper_title = pattern_match(doc_title.lower(), pattern) or pattern == "all"

            proper_sender = pattern_match_list(
                actor_email, details.get("allowed_to_send")
            ) or details.get("allowed_to_send") == {"all"}

            proper_receiver = pattern_match_list(
                target_user, details.get("allowed_to_receive")
            ) or details.get("allowed_to_receive") == {"all"}

            if (
                proper_title
                and proper_sender
                and proper_receiver
                and current_time < details.get("allowed_until")
            ):
                return False
        # No exceptions match.
        # Return the event summary (which is True) to alert & use in title.
        return {
            "actor": actor_email,
            "doc_title": doc_title,
            "target_user": target_user,
        }
    return False


def rule(event):
    application_name = event.deep_get("id", "applicationName")
    actor_email = event.deep_get("actor", "email", default="EMAIL_UNKNOWN")

    # For GSuite.ActivityEvent, each log is a single event (no events array)
    if application_name == "drive" and event.get("type") == "acl_change":
        # If this event is a dangerous file share, alert:
        return bool(_check_acl_change_event(actor_email, event))
    return False


def title(event):
    actor_email = event.deep_get("actor", "email", default="EMAIL_UNKNOWN")
    matching_event = _check_acl_change_event(actor_email, event)

    if matching_event:
        actor = matching_event.get("actor", "ACTOR_UNKNOWN")
        doc_title = matching_event.get("doc_title", "DOC_TITLE_UNKNOWN")
        target_user = matching_event.get("target_user", "USER_UNKNOWN")
        return f'Dangerous file share by [{actor}]: "{doc_title}" to {target_user}'
    return "No matching events, but DangerousShares still fired"
