from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "service_account_created"


def title(event):
    actor_email = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    svc_acct_name = deep_get(event, "resource", "name", default="<SVC_ACCT_NAME_NOT_FOUND>")
    return f"Asana user [{actor_email}] created a new service account [{svc_acct_name}]."
