def rule(event):
    if event.deep_get("action", default="") in [
        "migration.create",
        "org.transfer_outgoing",
        "org.transfer",
        "repo.transfer_outgoing",
    ]:
        return True
    return False
