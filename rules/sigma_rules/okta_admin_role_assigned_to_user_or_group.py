def rule(event):
    if event.deep_get("eventtype", default="") in [
        "group.privilege.grant",
        "user.account.privilege.grant",
    ]:
        return True
    return False
