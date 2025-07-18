def rule(event):
    if event.deep_get("action", default="") in [
        "org.remove_self_hosted_runner",
        "org.runner_group_created",
        "org.runner_group_removed",
        "org.runner_group_runner_removed",
        "org.runner_group_runners_added",
        "org.runner_group_runners_updated",
        "org.runner_group_updated",
        "repo.register_self_hosted_runner",
        "repo.remove_self_hosted_runner",
    ]:
        return True
    return False
