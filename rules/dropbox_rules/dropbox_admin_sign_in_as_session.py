from panther_base_helpers import deep_get


def rule(event):
    return deep_get(event, "event_type", "_tag", default="") == "sign_in_as_session_start"


def title(event):
    actor = deep_get(event, "actor", "admin", "email", default="<ACTOR_NOT_FOUND>")
    target = deep_get(event, "context", "email", default="<TARGET_NOT_FOUND>")
    return f"Dropbox: Admin [{actor}] started a sign-in-as session as user [{target}]."
