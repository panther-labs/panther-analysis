from panther_base_helpers import deep_get


def rule(event):
    if event.get("eventType") == "user.session.start":
        if deep_get(event, "outcome", "result") == "SUCCESS" and \
                event.udm("event_type") != "successful_login":
            return False
        if deep_get(event, "outcome", "result") == "FAILURE" and \
                event.udm("event_type") != "failed_login":
            return False

    return (
        event.udm("actor_user") == deep_get(event, "actor", "displayName") and
        event.udm("source_ip") == deep_get(event, "client", "ipAddress") and
        event.udm("user_agent") == deep_get(event, "client", "userAgent", "rawUserAgent")
     )
