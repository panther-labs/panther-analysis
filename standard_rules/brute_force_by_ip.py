"""
Searching logs in GSuite:

SELECT *
FROM panther_logs.public.gsuite_reports
WHERE id:applicationName = 'login'
AND events[0]:name = 'login_failure' LIMIT 10;
"""

import panther_event_type_helpers as event_type


def rule(event):
    # filter events on unified data model field
    return event.udm("event_type") == event_type.FAILED_LOGIN


def title(event):
    # use unified data model field in title
    return "{}: User [{}] from IP [{}] has exceeded the failed logins threshold".format(
        event.get("p_log_type"), event.udm("actor_user"), event.udm("source_ip")
    )
