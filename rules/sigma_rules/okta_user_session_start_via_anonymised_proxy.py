def rule(event):
    if all(
        [
            event.deep_get("eventtype", default="") == "user.session.start",
            event.deep_get("securitycontext", "isproxy", default="") == "true",
        ]
    ):
        return True
    return False
