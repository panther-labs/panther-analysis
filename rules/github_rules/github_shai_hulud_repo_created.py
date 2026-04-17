from panther_github_helpers import github_webhook_alert_context


def rule(event):
    if event.get("action") != "created":
        return False

    # Check if the repository description matches the Shai-Hulud indicator
    description = event.deep_get("repository", "description", default="")
    return description == "Sha1-Hulud: The Second Coming."


def title(event):
    repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
    user = event.deep_get("sender", "login", default="<UNKNOWN_USER>")
    return f"Sha1-Hulud malicious repository [{repo_name}] created by compromised user [{user}]"


def alert_context(event):
    context = github_webhook_alert_context(event)
    return context
