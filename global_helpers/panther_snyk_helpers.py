def snyk_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = event.get("userId", "<NO_USERID>")
    a_c["action"] = event.get("event", "<NO_EVENT>")
    for pass_thru in ["orgId", "groupId"]:
        a_c[pass_thru] = event.get(pass_thru, f"<NO_{pass_thru}>".upper())
    if (
        a_c.get("actor", "<NO_USERID>") != "<NO_USERID>"
        and a_c.get("groupId", "<NO_GROUPID>") != "<NO_GROUPID>"
    ):
        a_c[
            "actor_link"
        ] = f"https://app.snyk.io/group/{a_c.get('groupId')}/manage/member/{a_c.get('actor')}"
    return a_c
