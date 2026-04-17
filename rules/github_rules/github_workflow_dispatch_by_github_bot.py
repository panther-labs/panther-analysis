from panther_github_helpers import github_alert_context


def rule(event):

    return all(
        [
            event.get("programmatic_access_type") == "GitHub App server-to-server token",
            event.get("event") == "workflow_dispatch",
            event.get("actor") == "github-actions[bot]",
            event.get("action") == "workflows.created_workflow_run",
        ]
    )


def title(event):
    repo = event.get("repo", default="<NO_REPO>")
    workflow_name = event.get("name", default="<NO_WORKFLOW_NAME>")
    user = event.get("actor")
    return (
        f"Bot [{user}] manually triggered a "
        f"workflow dispatch for [{workflow_name}] "
        f"in [{repo}]"
    )


def alert_context(event):
    context = github_alert_context(event)
    context["workflow_name"] = event.get("name", "<NO_WORKFLOW_NAME>")
    context["workflow_id"] = event.get("workflow_id")
    context["workflow_run_id"] = event.get("workflow_run_id")
    context["head_branch"] = event.get("head_branch")
    context["head_sha"] = event.get("head_sha")
    context["programmatic_access_type"] = event.get("programmatic_access_type")
    context["token_id"] = event.get("token_id")
    context["workflow_run_link"] = (
        f"https://github.com/{context.get('repo')}/actions/"
        f"runs/{event.get('workflow_run_id', '<NO_RUN_ID>')}"
    )
    return context
