from panther_github_helpers import github_alert_context


def rule(event):

    return event.get("action").startswith("repository_ruleset.")


def title(event):
    action = "modified"
    if event.get("action").endswith("destroy"):
        action = "deleted"
    elif event.get("action").endswith("create"):
        action = "created"

    title_str = (
        f"Github repository ruleset for [{event.get('repo', '<UNKNOWN_REPO>')}]"
        f" {action} by [{event.get('actor','<UNKNOWN_ACTOR>')}]"
    )

    if event.get("ruleset_source_type", default="<UNKNOWN_SOURCE_TYPE>") == "Organization":
        title_str = (
            f"Github repository ruleset for Organization [{event.get('org', '<UNKNOWN_ORG>')}]"
            f" {action} by [{event.get('actor','<UNKNOWN_ACTOR>')}]"
        )
    return title_str


def dedup(event):
    return event.get("_document_id", "")


def severity(event):
    if event.get("action").endswith("create"):
        return "INFO"
    if event.get("action").endswith("update"):
        return "MEDIUM"
    if event.get("action").endswith("destroy"):
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    ctx = github_alert_context(event)
    ctx["user"] = event.get("actor", "")
    ctx["actor_is_bot"] = event.get("actor_is_bot", "")
    ctx["actor_user_agent"] = event.get("user_agent", "")
    ctx["business"] = event.get("business", "")
    ctx["public_repo"] = event.get("public_repo", "")
    ctx["operation_type"] = event.get("operation_type", "")
    ctx["ruleset_bypass_actors"] = event.deep_walk("ruleset_bypass_actors")
    ctx["ruleset_conditions"] = event.deep_walk("ruleset_conditions")
    ctx["ruleset_rules"] = event.deep_walk("ruleset_rules")
    return ctx
