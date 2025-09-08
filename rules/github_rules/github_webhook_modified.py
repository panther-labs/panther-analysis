from panther_github_helpers import github_alert_context


def rule(event):

    return event.get("action").startswith("hook.")


def title(event):
    repo = event.get("repo", "<UNKNOWN_REPO>")
    action = "modified"
    if event.get("action").endswith("destroy"):
        action = "deleted"
    elif event.get("action").endswith("create"):
        action = "created"

    title_str = (
        f"Github webhook [{event.deep_get('config','url',default='<UNKNOWN_URL>')}]"
        f" {action} by [{event.get('actor','<UNKNOWN_ACTOR>')}]"
    )
    if repo != "<UNKNOWN_REPO>":
        title_str += f" in repository [{repo}]"
    return title_str


def severity(event):
    if event.get("action").endswith("create"):
        return "MEDIUM"
    return "INFO"


def alert_context(event):
    ctx = github_alert_context(event)
    ctx["business"] = event.get("business", "")
    ctx["hook_id"] = event.get("hook_id", "")
    ctx["integration"] = event.get("integration", "")
    ctx["operation_type"] = event.get("operation_type", "")
    ctx["url"] = event.deep_get("config", "url", default="<UNKNOWN_URL>")
    return ctx
