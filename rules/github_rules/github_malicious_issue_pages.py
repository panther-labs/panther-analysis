from panther_github_helpers import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
)


def rule(event):
    # Check if this is an issue event (opened or edited) and that it's open
    is_issue_event = (
        event.get("issue")
        and event.get("action") in ["opened", "edited"]
        and event.deep_get("issue", "state") == "open"
    )

    # Check if this is a pages/wiki event (Gollum event)
    has_pages = event.get("pages")

    if not is_issue_event and not has_pages:
        return False

    # Check issue fields if this is an issue event
    if is_issue_event:
        fields_to_check = [
            event.deep_get("issue", "title"),
            event.deep_get("issue", "body"),
        ]

        for field in fields_to_check:
            if contains_bash_injection_pattern(field):
                return True

    # Check pages (for GitHub wiki/Gollum events)
    for page in event.get("pages", []):
        if contains_bash_injection_pattern(page.get("page_name")):
            return True

    return False


def title(event):
    repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")

    # If this is an issue event
    if event.get("issue"):
        issue_number = event.deep_get("issue", "number", default="<UNKNOWN_ISSUE_NUMBER>")
        user = event.deep_get("issue", "user", "login", default="<UNKNOWN_USER>")
        return (
            f"Malicious pattern detected in issue #{issue_number} in {repo_name} by user [{user}]"
        )

    # If this is a pages/wiki event
    if event.get("pages"):
        return f"Malicious pattern detected in wiki page in {repo_name}"

    return f"Malicious pattern detected in {repo_name}"


def alert_context(event):
    context = github_webhook_alert_context(event)

    # Analyze patterns found in issue fields if this is an issue event
    if event.get("issue"):
        issue_fields = {
            "title": event.deep_get("issue", "title"),
            "body": event.deep_get("issue", "body"),
        }

        context["field_analysis"] = {}
        for field_name, field_value in issue_fields.items():
            patterns = get_matched_bash_patterns(field_value)
            if patterns:
                context["field_analysis"][field_name] = {
                    "value": field_value,
                    "matched_patterns": patterns,
                }

        # Add issue details
        issue = event.get("issue", {})
        context["issue"] = {
            "number": issue.get("number"),
            "title": issue.get("title"),
            "state": issue.get("state"),
            "user": issue.get("user", {}).get("login"),
            "html_url": issue.get("html_url"),
            "created_at": issue.get("created_at"),
            "updated_at": issue.get("updated_at"),
        }

    # Analyze pages (for wiki/Gollum events)
    context["malicious_pages"] = []
    for page in event.get("pages", []):
        if page_name := page.get("page_name"):
            patterns = get_matched_bash_patterns(page_name)
            if patterns:
                context["malicious_pages"].append(
                    {
                        "page_name": page_name,
                        "action": page.get("action"),
                        "title": page.get("title"),
                        "html_url": page.get("html_url"),
                        "matched_patterns": patterns,
                    }
                )

    return context


def reference(event):
    # Try to get the issue URL
    issue_url = event.deep_get("issue", "html_url")
    if issue_url:
        return issue_url

    # Try to get a page URL if this is a pages/wiki event
    if pages := event.get("pages"):
        if pages and len(pages) > 0 and pages[0].get("html_url"):
            return pages[0].get("html_url")

    if reference_url := github_reference_url(event):
        return reference_url

    return "DEFAULT"
