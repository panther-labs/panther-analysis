def rule(event):
    if event.deep_get("action", default="") in [
        "business_secret_scanning.disable",
        "business_secret_scanning.disabled_for_new_repos",
        "repository_secret_scanning.disable",
        "secret_scanning_new_repos.disable",
        "secret_scanning.disable",
    ]:
        return True
    return False
