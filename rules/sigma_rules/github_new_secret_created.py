def rule(event):
    if event.deep_get("action", default="") in [
        "codespaces.create_an_org_secret",
        "environment.create_actions_secret",
        "org.create_actions_secret",
        "repo.create_actions_secret",
    ]:
        return True
    return False
