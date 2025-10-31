def rule(event):
    # Only check completed workflow jobs
    if event.get("action") != "completed":
        return False

    # GitHub-hosted runners always have "GitHub Actions" in the runner_name
    # Self-hosted runners cannot use this reserved name
    runner_name = event.deep_get("workflow_job", "runner_name", default="")

    # Must have a runner name and it must not be GitHub-hosted
    if not runner_name:
        return False

    return not runner_name.startswith("GitHub Actions")


def title(event):
    workflow_name = event.deep_get("workflow_job", "name", default="Unknown Workflow")
    repo_name = event.deep_get("repository", "full_name", default="Unknown Repository")
    runner_name = event.deep_get("workflow_job", "runner_name", default="Unknown Runner")

    return f"Self-hosted runner '{runner_name}' used in workflow '{workflow_name}' for {repo_name}"


def alert_context(event):
    workflow_job = event.get("workflow_job", {})
    repository = event.get("repository", {})

    return {
        "workflow_name": workflow_job.get("name"),
        "workflow_job_id": workflow_job.get("id"),
        "workflow_run_id": workflow_job.get("run_id"),
        "workflow_url": workflow_job.get("html_url"),
        "repository": repository.get("full_name"),
        "repository_private": repository.get("private"),
        "repository_visibility": repository.get("visibility"),
        "head_branch": workflow_job.get("head_branch"),
        "head_sha": workflow_job.get("head_sha"),
        "conclusion": workflow_job.get("conclusion"),
        "runner_name": workflow_job.get("runner_name"),
        "runner_group_name": workflow_job.get("runner_group_name"),
        "runner_id": workflow_job.get("runner_id"),
        "runner_group_id": workflow_job.get("runner_group_id"),
        "actor": event.deep_get("sender", "login"),
    }


def severity(event):
    # Public or forkable repos with self-hosted runners have a medium risk
    repo_visibility = event.deep_get("repository", "visibility")
    allow_forking = event.deep_get("repository", "allow_forking", default=False)
    is_private = event.deep_get("repository", "private", default=True)

    if repo_visibility == "public" or (not is_private) or allow_forking:
        return "MEDIUM"

    # Private, non-forkable repos are low risk
    return "INFO"
