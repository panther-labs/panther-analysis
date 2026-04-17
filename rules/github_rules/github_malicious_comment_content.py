from panther_github_helpers import (
    contains_bash_injection_pattern,
    get_matched_bash_patterns,
    github_reference_url,
    github_webhook_alert_context,
)


def rule(event):
    # Check for comment/review events
    action = event.get("action")

    # Handle issue_comment events (comments on issues or PRs)
    if event.get("comment") and action in ["created", "edited"]:
        if contains_bash_injection_pattern(event.deep_get("comment", "body")):
            return True

    # Handle pull_request_review events
    if event.get("review") and action in ["submitted", "edited"]:
        if contains_bash_injection_pattern(event.deep_get("review", "body")):
            return True
    return False


def title(event):
    repo_name = event.deep_get("repository", "full_name", default="<UNKNOWN_REPO>")
    action = event.get("action", "<UNKNOWN_ACTION>")

    # Determine if this is a comment or review
    if event.get("comment"):
        comment_id = event.deep_get("comment", "id", default="<UNKNOWN>")
        comment_type = "PR comment" if event.get("pull_request") else "issue comment"
        return (
            f"Malicious pattern detected in {comment_type} #{comment_id} in {repo_name} ({action})"
        )
    if event.get("review"):
        review_id = event.deep_get("review", "id", default="<UNKNOWN>")
        return f"Malicious pattern detected in PR review #{review_id} in {repo_name} ({action})"

    return f"Malicious pattern detected in comment/review in {repo_name} ({action})"


def alert_context(event):
    context = github_webhook_alert_context(event)

    # Analyze comment body
    if comment_body := event.deep_get("comment", "body"):
        patterns = get_matched_bash_patterns(comment_body)
        if patterns:
            comment = event.get("comment", {})
            context["comment_analysis"] = {
                "body": comment_body,
                "matched_patterns": patterns,
                "comment_id": comment.get("id"),
                "user": comment.get("user", {}).get("login"),
                "html_url": comment.get("html_url"),
                "created_at": comment.get("created_at"),
                "updated_at": comment.get("updated_at"),
            }

    # Analyze review body
    if review_body := event.deep_get("review", "body"):
        patterns = get_matched_bash_patterns(review_body)
        if patterns:
            review = event.get("review", {})
            context["review_analysis"] = {
                "body": review_body,
                "matched_patterns": patterns,
                "review_id": review.get("id"),
                "user": review.get("user", {}).get("login"),
                "state": review.get("state"),
                "html_url": review.get("html_url"),
                "submitted_at": review.get("submitted_at"),
            }

    return context


def reference(event):
    # Try to get comment or review URL
    if comment_url := event.deep_get("comment", "html_url"):
        return comment_url

    if review_url := event.deep_get("review", "html_url"):
        return review_url

    if reference_url := github_reference_url(event):
        return reference_url

    return "DEFAULT"
