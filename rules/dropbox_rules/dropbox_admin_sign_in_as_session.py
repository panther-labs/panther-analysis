def rule(event):
    return event.deep_get("event_type", "_tag", default="") == "sign_in_as_session_start"


def title(event):
    actor = event.deep_get("actor", "admin", "email", default="<ACTOR_NOT_FOUND>")
    target = event.deep_get("context", "email", default="<TARGET_NOT_FOUND>")
    return f"Dropbox: Admin [{actor}] started a sign-in-as session as user [{target}]."
