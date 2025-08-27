from panther_github_helpers import github_alert_context


def rule(event):
    if event.get("action") not in [
        "repo.create",
        "repo.access",
        "repo.download_zip",
        "team.add_repository",
    ]:
        return False

    if not event.get("public_repo"):
        return False

    return "s1ngularity-repository" in event.get("repo", "").lower()


def title(event):
    action = event.get("action", "Unknown").replace("repo.", "").title()
    actor = event.get("actor", "Unknown")
    repo = event.get("repo", "Unknown")

    return f"NX Supply Chain: [{repo}] {action} by {actor}"


def alert_context(event):
    return github_alert_context(event)


def severity(event):
    action = event.get("action", "")

    if action == "repo.create":
        return "CRITICAL"

    if action in ["repo.access", "repo.download_zip"]:
        return "HIGH"

    if action == "team.add_repository":
        return "MEDIUM"

    return "DEFAULT"
