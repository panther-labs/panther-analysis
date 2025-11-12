from panther_base_helpers import deep_get
from panther_github_helpers import is_cross_fork_pr


def rule(event):
    return (
        event.deep_get("workflow_run", "event") in ("pull_request_target", "pull_request")
        and event.get("action") == "requested"
        and is_cross_fork_pr(event) is True
    )


def title(event):
    workflow_name = event.deep_get("workflow_run", "name", default="<UNKNOWN_WORKFLOW>")
    repo_name = deep_get(event, "repository", "full_name", default="<UNKNOWN_REPO>")
    action = event.get("action", "<UNKNOWN_ACTION>")

    title_str = f"Workflow [{workflow_name}] triggered by cross-fork PR in {repo_name} ({action})"
    return title_str
