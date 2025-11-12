from panther_github_helpers import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
    is_cross_fork_pr,
    is_pull_request_event,
)


def rule(event):
    if not is_pull_request_event(event) or event.deep_get("action") != "opened":
        return False

    # Check all untrusted PR-related inputs
    fields_to_check = [
        event.deep_get("pull_request", "title"),
        event.deep_get("pull_request", "body"),
        event.deep_get("pull_request", "head", "ref"),
        event.deep_get("pull_request", "head", "label"),
        event.deep_get("pull_request", "head", "repo", "default_branch"),
    ]

    for field in fields_to_check:
        if contains_bash_injection_pattern(field):
            return True

    return False


def title(event):
    pr_number = event.deep_get("pull_request", "number", default="<UNKNOWN>")
    repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
    action = event.get("action", "<UNKNOWN_ACTION>")

    return f"Malicious pattern detected in PR #{pr_number} in {repo_name} ({action})"


def alert_context(event):
    context = github_webhook_alert_context(event)

    # Analyze patterns found in all PR fields
    pr_fields = {
        "title": event.deep_get("pull_request", "title"),
        "body": event.deep_get("pull_request", "body"),
        "head_ref": event.deep_get("pull_request", "head", "ref"),
        "head_label": event.deep_get("pull_request", "head", "label"),
        "head_repo_default_branch": event.deep_get(
            "pull_request", "head", "repo", "default_branch"
        ),
    }

    context["field_analysis"] = {}
    for field_name, field_value in pr_fields.items():
        patterns = get_matched_bash_patterns(field_value)
        if patterns:
            context["field_analysis"][field_name] = {
                "value": field_value,
                "matched_patterns": patterns,
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
