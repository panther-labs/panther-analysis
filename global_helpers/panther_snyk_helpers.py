def snyk_alert_context(event) -> dict:
    a_c = {}
    a_c["actor"] = event.get("userId", "<NO_USERID>")
    a_c["action"] = event.get("event", "<NO_EVENT>")
    for pass_thru in ["orgId", "groupId"]:
        a_c[pass_thru] = event.get(pass_thru, f"<NO_{pass_thru}>".upper())
    return a_c
