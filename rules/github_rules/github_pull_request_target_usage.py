from panther_base_helpers import deep_get
from panther_github_helpers import (
    github_reference_url,
    github_webhook_alert_context,
    is_cross_fork_pr,
)


def rule(event):
    return (
        event.deep_get("workflow_run", "event") == "pull_request_target"
        and event.get("action") == "completed"
    )


def title(event):
    workflow_name = event.deep_get("workflow_run", "name", default="<UNKNOWN_WORKFLOW>")
    repo_name = deep_get(event, "repository", "full_name", default="<UNKNOWN_REPO>")
    action = event.get("action", "<UNKNOWN_ACTION>")

    if is_cross_fork_pr(event):
        return (
            f"pull_request_target workflow [{workflow_name}] "
            f"triggered by cross-fork PR in {repo_name} ({action})"
        )
    return f"pull_request_target workflow [{workflow_name}] triggered in {repo_name} ({action})"


def alert_context(event):
    context = github_webhook_alert_context(event)

    workflow_run = event.get("workflow_run", {})
    if workflow_run:
        context["workflow_run"] = {
            "id": workflow_run.get("id"),
            "name": workflow_run.get("name"),
            "event": workflow_run.get("event"),
            "status": workflow_run.get("status"),
            "conclusion": workflow_run.get("conclusion"),
            "html_url": workflow_run.get("html_url"),
        }

    return context


def reference(event):
    if reference_url := github_reference_url(event):
        return reference_url

    return "DEFAULT"


def severity(event):
    if is_cross_fork_pr(event):
        return "DEFAULT"

    return "LOW"
