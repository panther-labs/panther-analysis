def rule(event):
    """Alert when a GitHub workflow job contains a checkout action step."""
    # Only check completed workflow jobs
    if event.get("action") != "completed":
        return False

    # Get the steps array from workflow_job
    steps = event.deep_get("workflow_job", "steps", default=[])

    # Iterate through each step and check if the name contains "checkout" (case-insensitive)
    for step in steps:
        step_name = step.get("name", "").lower()
        if "checkout" in step_name:
            return True

    return False


def title(event):
    """Generate a dynamic title for the alert."""
    workflow_name = event.deep_get("workflow_job", "name", default="Unknown Workflow")
    repo_name = event.deep_get("repository", "full_name", default="Unknown Repository")
    return f"Checkout action detected in workflow '{workflow_name}' for {repo_name}"


def alert_context(event):
    """Provide additional context for the alert."""
    workflow_job = event.get("workflow_job", {})
    repository = event.get("repository", {})

    # Find all checkout steps
    checkout_steps = []
    for step in workflow_job.get("steps", []):
        if "checkout" in step.get("name", "").lower():
            checkout_steps.append(
                {
                    "name": step.get("name"),
                    "number": step.get("number"),
                    "conclusion": step.get("conclusion"),
                }
            )

    return {
        "workflow_name": workflow_job.get("name"),
        "workflow_job_id": workflow_job.get("id"),
        "workflow_run_id": workflow_job.get("run_id"),
        "workflow_url": workflow_job.get("html_url"),
        "repository": repository.get("full_name"),
        "repository_private": repository.get("private"),
        "head_branch": workflow_job.get("head_branch"),
        "head_sha": workflow_job.get("head_sha"),
        "conclusion": workflow_job.get("conclusion"),
        "checkout_steps": checkout_steps,
        "actor": event.deep_get("sender", "login"),
    }
