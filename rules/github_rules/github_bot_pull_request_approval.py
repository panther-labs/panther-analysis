from panther_github_helpers import github_webhook_alert_context


def is_bot_reviewer(event):
    return event.deep_get("review", "user", "type", default="") == "Bot" or str(
        event.deep_get("review", "user", "login", default="")
    ).endswith("[bot]")


def rule(event):
    return (
        event.get("action") == "submitted"
        and event.deep_get("review", "state", default="") == "approved"
        and is_bot_reviewer(event)
    )


def title(event):
    reviewer = event.deep_get("review", "user", "login", default="<UNKNOWN_REVIEWER>")
    number = event.deep_get("pull_request", "number", default="<UNKNOWN>")
    repo = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
    return f"Bot [{reviewer}] approved pull request #{number} in [{repo}]"


def alert_context(event):
    context = github_webhook_alert_context(event)
    context["reviewer"] = event.deep_get("review", "user", "login")
    context["reviewer_type"] = event.deep_get("review", "user", "type")
    context["review_url"] = event.deep_get("review", "html_url")
    context["pull_request_number"] = event.deep_get("pull_request", "number")
    context["repository_full_name"] = event.deep_get("repository", "full_name")
    return context
