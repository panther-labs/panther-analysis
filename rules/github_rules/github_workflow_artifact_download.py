def rule(event):
    if event.get("action") != "completed":
        return False

    steps = event.deep_get("workflow_job", "steps", default=[])

    # Look for artifact download in step names
    for step in steps:
        step_name = step.get("name", "").lower()
        if any(
            pattern in step_name
            for pattern in [
                "download artifact",
                "download-artifact",
                "actions/download-artifact",
                "restore artifact",
                "get artifact",
                "fetch artifact",
                "pull artifact",
            ]
        ):
            return True

    return False


def title(event):
    workflow_name = event.deep_get("workflow_job", "name", default="Unknown Workflow")
    repo_name = event.deep_get("repository", "full_name", default="Unknown Repository")

    return f"Artifact download detected in workflow '{workflow_name}' for {repo_name}"
