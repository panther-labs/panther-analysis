from panther_github_helpers import github_webhook_alert_context


def rule(event):
    return (
        event.get("action") == "completed"
        and event.deep_get("workflow_run", "head_repository", "fork") is True
    )


def title(event):
    workflow_name = event.deep_get("workflow", "name", default="<UNKNOWN_WORKFLOW>")
    fork_name = event.deep_get(
        "workflow_run", "head_repository", "full_name", default="<UNKNOWN_REPO_NAME>"
    )
    committer = event.deep_get(
        "workflow_run", "head_commit", "author", "name", default="<UNKNOWN_COMMITTER_NAME>"
    )
    commit_id = event.deep_get("workflow_run", "head_commit", "id", default="<UNKNOWN_COMMIT_ID>")

    title_str = (
        f"Workflow [{workflow_name}] was triggered by"
        f" a forked repository {fork_name}"
        f" through a commit with id [{commit_id}] "
        f" pushed by user ({committer})"
    )
    return title_str


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
