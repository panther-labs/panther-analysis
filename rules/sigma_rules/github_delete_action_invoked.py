def rule(event):
    if event.deep_get("action", default="") in [
        "codespaces.delete",
        "environment.delete",
        "project.delete",
        "repo.destroy",
    ]:
        return True
    return False
