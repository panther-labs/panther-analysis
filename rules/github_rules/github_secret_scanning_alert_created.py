from global_filter_github import filter_include_event


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action", "") == "secret_scanning_alert.create"


def title(event):
    return (
        f"Github detected a secret in {event.get('repo', '<REPO_NOT_FOUND>')} "
        f"(#{event.get('number', '<NUMBER_NOT_FOUND>')})"
    )


def alert_context(event):
    return {
        "github_organization": event.get("org", "<ORG_NOT_FOUND>"),
        "github_repository": event.get("repo", "<REPO_NOT_FOUND>"),
        "alert_number": str(event.get("number", "<NUMBER_NOT_FOUND>")),
        "url": f"https://github.com/{event.get('repo')}/security/secret-scanning/"
        f"{event.get('number')}"
        if all([event.get("repo"), event.get("number")])
        else "<URL_NOT_FOUND>",
    }
