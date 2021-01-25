"""
Panther rule focused on detecting G Suite users who have shared a file with
an external user.

This SQL, when run in the Panther data explorer console (https://panther-internal.com/data-analytics/explorer/?selectedDatabase=panther_logs),
will find some example events:

```sql
WITH share_summary AS (select p_event_time,actor.email,
        element_at(filter(report_event.parameters,x->(x.name='visibility')),1).value as new_visibility,
        element_at(filter(report_event.parameters,x->(x.name='old_visibility')),1).value as old_visibility,
        element_at(filter(report_event.parameters,x->(x.name='target_user')),1).value as target_user,
        element_at(filter(report_event.parameters,x->(x.name='doc_title')),1).value as doc_title,
        element_at(filter(report_event.parameters,x->(x.name='owner')),1).value as owner,
        report_event
FROM gsuite_reports
CROSS JOIN UNNEST(events) as t(report_event)
WHERE id.applicationName = 'drive'
    and report_event.type='acl_change'
    and (report_event.name='change_user_access'
        or report_event.name='change_document_visibility'
        or report_event.name='change_document_access_scope')
    and year = 2021
    and month = 1
)
SELECT * from share_summary
WHERE
    old_visibility='private'
    and new_visibility='shared_externally'
    and target_user not like '%@acme.com'```

"""

import datetime
from panther_base_helpers import deep_get, pattern_match, pattern_match_list

COMPANY_DOMAIN = 'your-company-name.com'
EXCEPTION_PATTERNS = {
    # The glob pattern for the document title (lowercased)
    "document title p*": {
        # All actors allowed to receive the file share
        "allowed_for": {
            "alice@acme.com",
            "samuel@acme.com",
            "nathan@acme.com",
            "barry@acme.com",
            # Allow any user
            # "all"
            # Allow any user in a specific domain
            # "*@acme.com"
        },
        # The time limit for how long the file share stays valid
        "allowed_until": datetime.datetime(year=2030, month=6, day=2),
    },
}


def _check_acl_change_event(actor_email, acl_change_event):
    parameters = {
        p.get("name", ""): (p.get("value") or p.get("multiValue"))
        for p in acl_change_event["parameters"]
    }

    doc_title = parameters.get("doc_title", "TITLE_UNKNOWN")
    old_visibility = parameters.get("old_visibility", "OLD_VISIBILITY_UNKNOWN")
    new_visibility = parameters.get("visibility", "NEW_VISIBILITY_UNKNOWN")
    target_user = parameters.get("target_user", "USER_UNKNOWN")
    current_time = datetime.datetime.now()

    if (new_visibility == "shared_externally" and
            old_visibility == "private" and
            not target_user.endswith(f"@{COMPANY_DOMAIN}")):
        # This is a dangerous share, check exceptions:
        for pattern, details in EXCEPTION_PATTERNS.items():
            doc_title_match = pattern_match(doc_title.lower(), pattern)
            allowed_for_match = pattern_match_list(actor_email, details.get("allowed_for"))
            allowed_for_all_match = details.get("allowed_for") == {"all"}

            if (doc_title_match and
                    (allowed_for_match or allowed_for_all_match) and
                    current_time < details.get("allowed_until")):
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
    application_name = deep_get(event, 'id', 'applicationName')
    events = event.get("events")
    actor_email = deep_get(event, 'actor', 'email', default="EMAIL_UNKNOWN")

    if (application_name == "drive" and events and
            "acl_change" in set(e["type"] for e in events)):
        # If any of the events in this record are a dangerous file share, alert:
        return any(
            _check_acl_change_event(actor_email, acl_change_event)
            for acl_change_event in events)
    return False


def title(event):
    events = event.get("events", [])
    actor_email = deep_get(event, 'actor', 'email', default='EMAIL_UNKNOWN')
    matching_events = [
        _check_acl_change_event(actor_email, acl_change_event)
        for acl_change_event in events
        if _check_acl_change_event(actor_email, acl_change_event)
    ]

    if matching_events:
        len_events = len(matching_events)
        first_event = matching_events[0]
        actor = first_event.get("actor", "ACTOR_UNKNOWN")
        doc_title = first_event.get("doc_title", "DOC_TITLE_UNKNOWN")
        target_user = first_event.get("target_user", "USER_UNKNOWN")
        if len(matching_events) > 1:
            return f'Multiple dangerous shares ({len_events}) by [{actor}], including "{doc_title}" to {target_user}'
        return f'Dangerous file share by [{actor}]: "{doc_title}" to {target_user}'
    # How could there not be if title() gets called?
    return "ERROR - No matching events, but DangerousShares still fired?"
